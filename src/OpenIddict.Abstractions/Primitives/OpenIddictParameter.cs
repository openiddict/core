/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.Json;

#if SUPPORTS_JSON_NODES
using System.Text.Json.Nodes;
#endif

namespace OpenIddict.Abstractions;

/// <summary>
/// Represents an OpenIddict parameter value, that can be either a primitive value,
/// an array of strings or a complex JSON representation containing child nodes.
/// </summary>
public readonly struct OpenIddictParameter : IEquatable<OpenIddictParameter>
{
    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(bool value) => Value = value;

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(bool? value) => Value = value;

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(JsonElement value) => Value = value;

#if SUPPORTS_JSON_NODES
    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(JsonNode? value) => Value = value;
#endif

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(long value) => Value = value;

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(long? value) => Value = value;

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(string? value) => Value = value;

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(string?[]? value) => Value = value;

    /// <summary>
    /// Gets the child item corresponding to the specified index.
    /// </summary>
    /// <param name="index">The index of the child item.</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance containing the item value.</returns>
    public OpenIddictParameter? this[int index] => GetUnnamedParameter(index);

    /// <summary>
    /// Gets the child item corresponding to the specified name.
    /// </summary>
    /// <param name="name">The name of the child item.</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance containing the item value.</returns>
    public OpenIddictParameter? this[string name] => GetNamedParameter(name);

    /// <summary>
    /// Gets the number of named or unnamed child items contained in the current parameter or 0
    /// if the parameter doesn't represent an array of strings, a JSON array or a JSON object.
    /// </summary>
    public int Count
    {
        get
        {
            return Value switch
            {
                // If the parameter is a primitive array of strings, return its length.
                string?[] value => value.Length,

                // If the parameter is a JSON array or a JSON object, return its length.
                JsonElement { ValueKind: JsonValueKind.Array or JsonValueKind.Object } element
                    => Count(element),

#if SUPPORTS_JSON_NODES
                // If the parameter is a JsonArray, return its length.
                JsonArray value => value.Count,

                // If the parameter is a JsonObject, return its length.
                JsonObject value => value.Count,

                // If the parameter is a JsonValue wrapping a JsonElement,
                // apply the same logic as with direct JsonElement instances.
                JsonValue value when value.TryGetValue(out JsonElement element)
                    => element.ValueKind is JsonValueKind.Array or JsonValueKind.Object ? Count(element) : 0,

                // If the parameter is a JsonValue wrapping a well-known primitive type
                // (e.g int or string), always return 0 as these types can't have a length.
                JsonValue value when value.TryGetValue(out bool    _) ||
                                     value.TryGetValue(out int     _) ||
                                     value.TryGetValue(out long    _) ||
                                     value.TryGetValue(out string? _) => 0,

                // If the parameter is any other JsonNode (e.g a JsonValue), serialize it
                // to a JsonElement first to determine its actual JSON representation
                // and extract the number of items if the element is a JSON array or object.
                JsonNode value when JsonSerializer.SerializeToElement(value)
                    is JsonElement { ValueKind: JsonValueKind.Array or JsonValueKind.Object } element
                    => Count(element),
#endif
                // Otherwise, return 0.
                _ => 0
            };

            static int Count(JsonElement element)
            {
                switch (element.ValueKind)
                {
                    case JsonValueKind.Array:
                        return element.GetArrayLength();

                    case JsonValueKind.Object:
                        var count = 0;

                        using (var enumerator = element.EnumerateObject())
                        {
                            checked
                            {
                                while (enumerator.MoveNext())
                                {
                                    count++;
                                }
                            }
                        }

                        return count;

                    default: return 0;
                }
            }
        }
    }

    /// <summary>
    /// Gets the associated value, that can be either a primitive CLR type
    /// (e.g bool, string, long), an array of strings or a complex JSON object.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public object? Value { get; }

    /// <summary>
    /// Determines whether the current <see cref="OpenIddictParameter"/>
    /// instance is equal to the specified <see cref="OpenIddictParameter"/>.
    /// </summary>
    /// <param name="other">The other object to which to compare this instance.</param>
    /// <returns>
    /// <see langword="true"/> if the two instances have both the same representation
    /// (e.g <see cref="string"/>) and value, <see langword="false"/> otherwise.
    /// </returns>
    public bool Equals(OpenIddictParameter other)
    {
        return (left: Value, right: other.Value) switch
        {
            // If the two parameters reference the same instance, return true.
            //
            // Note: true will also be returned if the two parameters are null.
            var (left, right) when ReferenceEquals(left, right) => true,

            // If one of the two parameters is null, return false.
            (null, _) or (_, null) => false,

            // If the two parameters are booleans, compare them directly.
            (bool left, bool right) => left == right,

            // If the two parameters are integers, compare them directly.
            (long left, long right) => left == right,

            // If the two parameters are strings, use string.Equals().
            (string left, string right) => string.Equals(left, right, StringComparison.Ordinal),

            // If the two parameters are string arrays, use SequenceEqual().
            (string?[] left, string?[] right) => Enumerable.SequenceEqual(left, right),

            // If one of the two parameters is an undefined JsonElement, treat it
            // as a null value and return true if the other parameter is null too.
            (JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined }, var right)
                => right is null,

            (var left, JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined })
                => left is null,

            // If the two parameters are JsonElement instances, use the custom comparer.
            (JsonElement left, JsonElement right) => DeepEquals(left, right),

            // When one of the parameters is a JsonElement, compare their underlying values.
            (JsonElement { ValueKind: JsonValueKind.True }, bool right) => right,
            (bool left, JsonElement { ValueKind: JsonValueKind.True })  => left,

            (JsonElement { ValueKind: JsonValueKind.False }, bool right) => !right,
            (bool left, JsonElement { ValueKind: JsonValueKind.False })  => !left,

            (JsonElement { ValueKind: JsonValueKind.Number } left, long right)
                when left.TryGetInt64(out var result) => result == right,

            (long left, JsonElement { ValueKind: JsonValueKind.Number } right)
                when right.TryGetInt64(out var result) => left == result,

            (JsonElement { ValueKind: JsonValueKind.String } left, string right)
                => string.Equals(left.GetString(), right, StringComparison.Ordinal),

            (string left, JsonElement { ValueKind: JsonValueKind.String } right)
                => string.Equals(left, right.GetString(), StringComparison.Ordinal),

#if SUPPORTS_JSON_NODES
            // When one of the parameters is a JsonValue, try to compare their underlying values
            // if the wrapped type is a common CLR primitive type to avoid the less efficient
            // JsonElement-based comparison, that requires doing a full JSON serialization.
            (JsonValue left, bool right) when  left.TryGetValue(out bool result) => result == right,
            (bool left, JsonValue right) when right.TryGetValue(out bool result) => result == left,

            (JsonValue left, long right) when  left.TryGetValue(out int result) => result == right,
            (long left, JsonValue right) when right.TryGetValue(out int result) => result == left,

            (JsonValue left, long right) when  left.TryGetValue(out long result) => result == right,
            (long left, JsonValue right) when right.TryGetValue(out long result) => result == left,

            (JsonValue left, string right) when left.TryGetValue(out string? result)
                => string.Equals(result, right, StringComparison.Ordinal),

            (string left, JsonValue right) when right.TryGetValue(out string? result)
                => string.Equals(left, result, StringComparison.Ordinal),
#endif
            // Otherwise, serialize both values to JsonElement and compare them.
#if SUPPORTS_DIRECT_JSON_ELEMENT_SERIALIZATION
            var (left, right) => DeepEquals(
                JsonSerializer.SerializeToElement(left, left.GetType()),
                JsonSerializer.SerializeToElement(right, right.GetType()))
#else
            var (left, right) => DeepEquals(
                JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(left, left.GetType())),
                JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(right, right.GetType())))
#endif
        };

        static bool DeepEquals(JsonElement left, JsonElement right)
        {
            RuntimeHelpers.EnsureSufficientExecutionStack();

            switch ((left.ValueKind, right.ValueKind))
            {
                case (JsonValueKind.Undefined, JsonValueKind.Undefined):
                case (JsonValueKind.Null,      JsonValueKind.Null):
                case (JsonValueKind.False,     JsonValueKind.False):
                case (JsonValueKind.True,      JsonValueKind.True):
                    return true;

                // Treat undefined JsonElement instances as null values.
                case (JsonValueKind.Undefined, JsonValueKind.Null):
                case (JsonValueKind.Null, JsonValueKind.Undefined):
                    return true;

                case (JsonValueKind.Number, JsonValueKind.Number):
                    return string.Equals(left.GetRawText(), right.GetRawText(), StringComparison.Ordinal);

                case (JsonValueKind.String, JsonValueKind.String):
                    return string.Equals(left.GetString(), right.GetString(), StringComparison.Ordinal);

                case (JsonValueKind.Array, JsonValueKind.Array):
                {
                    var length = left.GetArrayLength();
                    if (length != right.GetArrayLength())
                    {
                        return false;
                    }

                    for (var index = 0; index < length; index++)
                    {
                        if (!DeepEquals(left[index], right[index]))
                        {
                            return false;
                        }
                    }

                    return true;
                }

                case (JsonValueKind.Object, JsonValueKind.Object):
                {
                    foreach (var property in left.EnumerateObject())
                    {
                        if (!right.TryGetProperty(property.Name, out JsonElement element) ||
                            property.Value.ValueKind != element.ValueKind)
                        {
                            return false;
                        }

                        if (!DeepEquals(property.Value, element))
                        {
                            return false;
                        }
                    }

                    return true;
                }

                default: return false;
            }
        }
    }

    /// <summary>
    /// Determines whether the current <see cref="OpenIddictParameter"/>
    /// instance is equal to the specified <see cref="object"/>.
    /// </summary>
    /// <param name="obj">The other object to which to compare this instance.</param>
    /// <returns>
    /// <see langword="true"/> if the two instances have both the same representation
    /// (e.g <see cref="string"/>) and value, <see langword="false"/> otherwise.
    /// </returns>
    public override bool Equals(object? obj) => obj is OpenIddictParameter parameter && Equals(parameter);

    /// <summary>
    /// Returns the hash code of the current <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <returns>The hash code for the current instance.</returns>
    public override int GetHashCode()
    {
        return Value switch
        {
            // When the parameter value is null, return 0.
            null => 0,

            // When the parameter is an array of strings, compute the hash code of its items to
            // match the logic used when treating a JsonElement instance representing an array.
            string?[] value => GetHashCodeFromArray(value),

            // When the parameter is a JsonElement, compute its hash code.
            JsonElement value => GetHashCodeFromJsonElement(value),

#if SUPPORTS_JSON_NODES
            // When the parameter is a JsonValue wrapping a JsonElement,
            // apply the same logic as with direct JsonElement instances.
            JsonValue value when value.TryGetValue(out JsonElement element)
                => GetHashCodeFromJsonElement(element),

            // When the parameter is a JsonValue, compute the hash code of its underlying value
            // if the wrapped type is a common CLR primitive type to avoid the less efficient
            // JsonElement-based computation, that requires doing a full JSON serialization.
            JsonValue value when value.TryGetValue(out bool result) => result.GetHashCode(),

            JsonValue value when value.TryGetValue(out int  result) => result.GetHashCode(),
            JsonValue value when value.TryGetValue(out long result) => result.GetHashCode(),

            JsonValue value when value.TryGetValue(out string? result) => result.GetHashCode(),

            // When the parameter is a JsonNode (e.g a JsonValue wrapping a non-primitive type),
            // serialize it to a JsonElement first to determine its actual JSON representation
            // and apply the same logic as with non-wrapped JsonElement instances.
            JsonNode value when JsonSerializer.SerializeToElement(value) is JsonElement element
                => GetHashCodeFromJsonElement(element),
#endif
            // Otherwise, use the default hash code method.
            var value => value.GetHashCode()
        };

        static int GetHashCodeFromArray(string?[] array)
        {
            var hash = new HashCode();

            for (var index = 0; index < array.Length; index++)
            {
                hash.Add(array[index]);
            }

            return hash.ToHashCode();
        }

        static int GetHashCodeFromJsonElement(JsonElement element)
        {
            RuntimeHelpers.EnsureSufficientExecutionStack();

            switch (element.ValueKind)
            {
                case JsonValueKind.Undefined:
                case JsonValueKind.Null:
                    return 0;

                case JsonValueKind.True:
                    return true.GetHashCode();

                case JsonValueKind.False:
                    return false.GetHashCode();

                case JsonValueKind.Number when element.TryGetInt64(out var result):
                    return result.GetHashCode();

                case JsonValueKind.Number:
                    return element.GetRawText().GetHashCode();

                case JsonValueKind.String:
                    return element.GetString()!.GetHashCode();

                case JsonValueKind.Array:
                {
                    var hash = new HashCode();

                    foreach (var item in element.EnumerateArray())
                    {
                        hash.Add(GetHashCodeFromJsonElement(item));
                    }

                    return hash.ToHashCode();
                }

                case JsonValueKind.Object:
                {
                    var hash = new HashCode();

                    foreach (var property in element.EnumerateObject())
                    {
                        hash.Add(property.Name);
                        hash.Add(GetHashCodeFromJsonElement(property.Value));
                    }

                    return hash.ToHashCode();
                }

                default: return 0;
            }
        }
    }

    /// <summary>
    /// Gets the child item corresponding to the specified name.
    /// </summary>
    /// <param name="name">The name of the child item.</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance containing the item value.</returns>
    public OpenIddictParameter? GetNamedParameter(string name)
        => TryGetNamedParameter(name, out var value) ? value : (OpenIddictParameter?) null;

    /// <summary>
    /// Gets the child item corresponding to the specified index.
    /// </summary>
    /// <param name="index">The index of the child item.</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance containing the item value.</returns>
    public OpenIddictParameter? GetUnnamedParameter(int index)
        => TryGetUnnamedParameter(index, out var value) ? value : (OpenIddictParameter?) null;

    /// <summary>
    /// Gets the named child items associated with the current parameter, if it represents a JSON object.
    /// Note: if the JSON object contains multiple parameters with the same name, only the last occurrence is returned.
    /// </summary>
    /// <returns>A dictionary of all the parameters associated with the current instance.</returns>
    public IReadOnlyDictionary<string, OpenIddictParameter> GetNamedParameters()
    {
        return Value switch
        {
            // When the parameter is a JsonElement representing an object, return the requested item.
            JsonElement { ValueKind: JsonValueKind.Object } value => GetParametersFromJsonElement(value),

#if SUPPORTS_JSON_NODES
            // When the parameter is a JsonObject, return the requested item.
            JsonObject value => GetParametersFromJsonNode(value),

            // When the parameter is a JsonNode (e.g a JsonValue wrapping a non-primitive type),
            // serialize it to a JsonElement first to determine its actual JSON representation
            // and apply the same logic as with non-wrapped JsonElement instances.
            JsonNode value when JsonSerializer.SerializeToElement(value)
                is JsonElement { ValueKind: JsonValueKind.Object } element
                => GetParametersFromJsonElement(element),
#endif
            _ => ImmutableDictionary.Create<string, OpenIddictParameter>(StringComparer.Ordinal)
        };

        static IReadOnlyDictionary<string, OpenIddictParameter> GetParametersFromJsonElement(JsonElement element)
        {
            var parameters = new Dictionary<string, OpenIddictParameter>(StringComparer.Ordinal);

            foreach (var property in element.EnumerateObject())
            {
                parameters[property.Name] = new(property.Value);
            }

            return parameters;
        }

#if SUPPORTS_JSON_NODES

        static IReadOnlyDictionary<string, OpenIddictParameter> GetParametersFromJsonNode(JsonObject node)
        {
            var parameters = new Dictionary<string, OpenIddictParameter>(node.Count, StringComparer.Ordinal);

            foreach (var property in node)
            {
                parameters[property.Key] = new(property.Value);
            }

            return parameters;
        }
#endif
    }

    /// <summary>
    /// Gets the unnamed child items associated with the current parameter,
    /// if it represents an array of strings or a JSON array.
    /// </summary>
    /// <returns>An enumeration of all the unnamed parameters associated with the current instance.</returns>
    public IReadOnlyList<OpenIddictParameter> GetUnnamedParameters()
    {
        return Value switch
        {
            // When the parameter is an array of strings, return its items.
            string?[] value => GetParametersFromArray(value),

            // When the parameter is a JsonElement representing an array, return its children.
            JsonElement { ValueKind: JsonValueKind.Array } value => GetParametersFromJsonElement(value),

#if SUPPORTS_JSON_NODES
            // When the parameter is a JsonArray, return its children.
            JsonArray value => GetParametersFromJsonNode(value),

            // When the parameter is a JsonNode (e.g a JsonValue wrapping a non-primitive type),
            // serialize it to a JsonElement first to determine its actual JSON representation
            // and apply the same logic as with non-wrapped JsonElement instances.
            JsonNode value when JsonSerializer.SerializeToElement(value)
                is JsonElement { ValueKind: JsonValueKind.Array } element
                => GetParametersFromJsonElement(element),
#endif
            _ => ImmutableList.Create<OpenIddictParameter>()
        };

        static IReadOnlyList<OpenIddictParameter> GetParametersFromArray(string?[] array)
        {
            var parameters = new OpenIddictParameter[array.Length];

            for (var index = 0; index < array.Length; index++)
            {
                parameters[index] = new(array[index]);
            }

            return parameters;
        }

        static IReadOnlyList<OpenIddictParameter> GetParametersFromJsonElement(JsonElement element)
        {
            var length = element.GetArrayLength();
            var parameters = new OpenIddictParameter[length];

            for (var index = 0; index < length; index++)
            {
                parameters[index] = new(element[index]);
            }

            return parameters;
        }

#if SUPPORTS_JSON_NODES
        static IReadOnlyList<OpenIddictParameter> GetParametersFromJsonNode(JsonArray node)
        {
            var parameters = new OpenIddictParameter[node.Count];

            for (var index = 0; index < node.Count; index++)
            {
                parameters[index] = new(node[index]);
            }

            return parameters;
        }
#endif
    }

    /// <summary>
    /// Returns the <see cref="string"/> representation of the current instance.
    /// </summary>
    /// <returns>The <see cref="string"/> representation associated with the parameter value.</returns>
    public override string? ToString() => Value switch
    {
        null => string.Empty,

        bool value => value ? "true" : "false",
        long value => value.ToString(CultureInfo.InvariantCulture),

        string    value => value,
        string?[] value => string.Join(", ", value),

        JsonElement { ValueKind: JsonValueKind.True  } => "true",
        JsonElement { ValueKind: JsonValueKind.False } => "false",

        JsonElement value => value.ToString(),

#if SUPPORTS_JSON_NODES
        JsonValue value when value.TryGetValue(out JsonElement element)
            => element.ValueKind switch
            {
                JsonValueKind.True  => "true",
                JsonValueKind.False => "false",

                _ => element.ToString()
            },
        
        JsonValue value when value.TryGetValue(out bool result)
            => result ? "true" : "false",
        
        JsonValue value when value.TryGetValue(out int result)
            => result.ToString(CultureInfo.InvariantCulture),

        JsonValue value when value.TryGetValue(out long result)
            => result.ToString(CultureInfo.InvariantCulture),

        JsonValue value when value.TryGetValue(out string? result) => result,

        JsonNode value when JsonSerializer.SerializeToElement(value) is JsonElement element
            => element.ValueKind switch
            {
                JsonValueKind.True  => "true",
                JsonValueKind.False => "false",

                _ => element.ToString()
            },
#endif
        _ => string.Empty
    };

    /// <summary>
    /// Tries to get the child item corresponding to the specified name.
    /// </summary>
    /// <param name="name">The name of the child item.</param>
    /// <param name="value">An <see cref="OpenIddictParameter"/> instance containing the item value.</param>
    /// <returns><see langword="true"/> if the parameter could be found, <see langword="false"/> otherwise.</returns>
    public bool TryGetNamedParameter(string name, out OpenIddictParameter value)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0192), nameof(name));
        }

        var result = Value switch
        {
            // When the parameter is a JsonElement representing an array, return the requested item.
            JsonElement { ValueKind: JsonValueKind.Object } element =>
                element.TryGetProperty(name, out JsonElement property) ? new(property) : null,

#if SUPPORTS_JSON_NODES
            // When the parameter is a JsonObject, return the requested item.
            JsonObject node => node.TryGetPropertyValue(name, out JsonNode? property) ? new(property) : null,

            // When the parameter is a JsonNode (e.g a JsonValue wrapping a non-primitive type),
            // serialize it to a JsonElement first to determine its actual JSON representation
            // and apply the same logic as with non-wrapped JsonElement instances.
            JsonNode node when JsonSerializer.SerializeToElement(node)
                is JsonElement { ValueKind: JsonValueKind.Object } element
                => element.TryGetProperty(name, out JsonElement property) ? new(property) : null,
#endif
            _ => (OpenIddictParameter?) null
        };

        value = result.GetValueOrDefault();
        return result.HasValue;
    }

    /// <summary>
    /// Tries to get the child item corresponding to the specified index.
    /// </summary>
    /// <param name="index">The index of the child item.</param>
    /// <param name="value">An <see cref="OpenIddictParameter"/> instance containing the item value.</param>
    /// <returns><see langword="true"/> if the parameter could be found, <see langword="false"/> otherwise.</returns>
    public bool TryGetUnnamedParameter(int index, out OpenIddictParameter value)
    {
        if (index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index), SR.GetResourceString(SR.ID0193));
        }

        var result = Value switch
        {
            // When the parameter is an array of strings, return the requested item.
            string?[] array => index < array.Length ? new(array[index]) : null,

            // When the parameter is a JsonElement representing an array, return the requested item.
            JsonElement { ValueKind: JsonValueKind.Array } element =>
                index < element.GetArrayLength() ? new(element[index]) : null,

#if SUPPORTS_JSON_NODES
            // When the parameter is a JsonArray, return the requested item.
            JsonArray node => index < node.Count ? new(node[index]) : null,

            // When the parameter is a JsonNode (e.g a JsonValue wrapping a non-primitive type),
            // serialize it to a JsonElement first to determine its actual JSON representation
            // and apply the same logic as with non-wrapped JsonElement instances.
            JsonNode node when JsonSerializer.SerializeToElement(node)
                is JsonElement { ValueKind: JsonValueKind.Array } element
                => index < element.GetArrayLength() ? new(element) : null,
#endif
            _ => (OpenIddictParameter?) null
        };

        value = result.GetValueOrDefault();
        return result.HasValue;
    }

    /// <summary>
    /// Writes the parameter value to the specified JSON writer.
    /// </summary>
    /// <param name="writer">The UTF-8 JSON writer.</param>
    public void WriteTo(Utf8JsonWriter writer)
    {
        if (writer is null)
        {
            throw new ArgumentNullException(nameof(writer));
        }

        switch (Value)
        {
            // Note: undefined JsonElement values are assimilated to null values.
            case null:
            case JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined }:
                writer.WriteNullValue();
                break;

            case bool value:
                writer.WriteBooleanValue(value);
                break;

            case long value:
                writer.WriteNumberValue(value);
                break;

            case string value:
                writer.WriteStringValue(value);
                break;

            case string?[] value:
                writer.WriteStartArray();

                for (var index = 0; index < value.Length; index++)
                {
                    writer.WriteStringValue(value[index]);
                }

                writer.WriteEndArray();
                break;

            case JsonElement value:
                value.WriteTo(writer);
                break;

#if SUPPORTS_JSON_NODES
            case JsonNode value:
                value.WriteTo(writer);
                break;
#endif
        }
    }

    /// <summary>
    /// Determines whether two <see cref="OpenIddictParameter"/> instances are equal.
    /// </summary>
    /// <param name="left">The first instance.</param>
    /// <param name="right">The second instance.</param>
    /// <returns><see langword="true"/> if the two instances are equal, <see langword="false"/> otherwise.</returns>
    public static bool operator ==(OpenIddictParameter left, OpenIddictParameter right) => left.Equals(right);

    /// <summary>
    /// Determines whether two <see cref="OpenIddictParameter"/> instances are not equal.
    /// </summary>
    /// <param name="left">The first instance.</param>
    /// <param name="right">The second instance.</param>
    /// <returns><see langword="true"/> if the two instances are not equal, <see langword="false"/> otherwise.</returns>
    public static bool operator !=(OpenIddictParameter left, OpenIddictParameter right) => !left.Equals(right);

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a boolean.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator bool(OpenIddictParameter? parameter)
        => ((bool?) parameter).GetValueOrDefault();

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a nullable boolean.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator bool?(OpenIddictParameter? parameter)
    {
        return parameter?.Value switch
        {
            // When the parameter is a null value or a JsonElement representing null, return null.
            null or JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } => null,

            // When the parameter is a boolean value, return it as-is.
            bool value => value,

            // When the parameter is a string value, try to parse it.
            string value => bool.TryParse(value, out var result) ? result : null,

            // When the parameter is a JsonElement, try to convert it if it's of a supported type.
            JsonElement value => ConvertFromJsonElement(value),

#if SUPPORTS_JSON_NODES
            // When the parameter is a JsonValue wrapping a JsonElement,
            // apply the same logic as with direct JsonElement instances.
            JsonValue value when value.TryGetValue(out JsonElement element) => ConvertFromJsonElement(element),

            // When the parameter is a JsonValue wrapping a boolean, return it as-is.
            JsonValue value when value.TryGetValue(out bool result) => result,

            // When the parameter is a JsonValue wrapping a string, try to parse it.
            JsonValue value when value.TryGetValue(out string? text) =>
                bool.TryParse(text, out var result) ? result : null,

            // When the parameter is a JsonNode (e.g a JsonValue wrapping a non-primitive type),
            // serialize it to a JsonElement first to determine its actual JSON representation
            // and apply the same logic as with non-wrapped JsonElement instances.
            JsonNode value when JsonSerializer.SerializeToElement(value) is JsonElement element
                => ConvertFromJsonElement(element),
#endif
            // If the parameter is of a different type, return null to indicate the conversion failed.
            _ => null
        };

        static bool? ConvertFromJsonElement(JsonElement element) => element.ValueKind switch
        {
            // When the parameter is a JsonElement representing a boolean, return it as-is.
            JsonValueKind.True  => true,
            JsonValueKind.False => false,

            // When the parameter is a JsonElement representing a string, try to parse it.
            JsonValueKind.String => bool.TryParse(element.GetString(), out var result) ? result : null,

            _ => null
        };
    }

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a <see cref="JsonElement"/>.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator JsonElement(OpenIddictParameter? parameter)
    {
        return parameter?.Value switch
        {
            // When the parameter is a null value, return an undefined JsonElement.
            null => default,

            // When the parameter is already a JsonElement, return it as-is.
            JsonElement value => value,

#if SUPPORTS_JSON_NODES
            // When the parameter is JsonNode, serialize it as a JsonElement.
            JsonNode value => JsonSerializer.SerializeToElement(value),
#endif
            // When the parameter is a string starting with '{' or '[' (which would correspond
            // to a JSON object or array), try to deserialize it to get a JsonElement instance.
            string { Length: > 0 } value when value[0] is '{' or '[' =>
                DeserializeElement(value) ??
                DeserializeElement(JsonSerializer.Serialize(value)) ?? default,

            // Otherwise, serialize it to get a JsonElement instance.
#if SUPPORTS_DIRECT_JSON_ELEMENT_SERIALIZATION
            object value => JsonSerializer.SerializeToElement(value, value.GetType())
#else
            object value => DeserializeElement(JsonSerializer.Serialize(value)) ?? default
#endif
        };

        static JsonElement? DeserializeElement(string value)
        {
            try
            {
                using var document = JsonDocument.Parse(value);
                return document.RootElement.Clone();
            }

            catch (JsonException)
            {
                return null;
            }
        }
    }

#if SUPPORTS_JSON_NODES
    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a <see cref="JsonNode"/>.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator JsonNode?(OpenIddictParameter? parameter)
    {
        return parameter?.Value switch
        {
            // When the parameter is a null value or a JsonElement representing null, return null.
            null or JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } => null,

            // When the parameter is already a JsonNode, return it as-is.
            JsonNode value => value,

            // When the parameter is a boolean, return a JsonValue.
            bool value => JsonValue.Create(value),

            // When the parameter is an integer, return a JsonValue.
            long value => JsonValue.Create(value),

            // When the parameter is a string starting with '{' or '[' (which would correspond
            // to a JSON object or array), try to deserialize it to get a JsonNode instance.
            string { Length: > 0 } value when value[0] is '{' or '[' => DeserializeNode(value),

            // When the parameter is a string, return a JsonValue.
            string value => JsonValue.Create(value),

            // When the parameter is an array of strings, return a JsonArray.
            string?[] value => CreateArray(value),

            // When the parameter is JsonElement, deserialize it as a JsonNode.
            JsonElement value => JsonSerializer.Deserialize<JsonNode>(value),

            // If the parameter is of a different type, return null to indicate the conversion failed.
            _ => null
        };

        static JsonNode? DeserializeNode(string value)
        {
            try
            {
                return JsonNode.Parse(value);
            }

            catch (JsonException)
            {
                return null;
            }
        }

        static JsonArray? CreateArray(string?[] values)
        {
            var array = new JsonArray();

            for (var index = 0; index < values.Length; index++)
            {
                array.Add(values[index]);
            }

            return array;
        }
    }

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a <see cref="JsonArray"/>.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator JsonArray?(OpenIddictParameter? parameter)
        => ((JsonNode?) parameter) as JsonArray;

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a <see cref="JsonObject"/>.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator JsonObject?(OpenIddictParameter? parameter)
        => ((JsonNode?) parameter) as JsonObject;

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a <see cref="JsonValue"/>.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator JsonValue?(OpenIddictParameter? parameter)
        => ((JsonNode?) parameter) as JsonValue;
#endif

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a long integer.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator long(OpenIddictParameter? parameter)
        => ((long?) parameter).GetValueOrDefault();

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a nullable long integer.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator long?(OpenIddictParameter? parameter)
    {
        return parameter?.Value switch
        {
            // When the parameter is a null value or a JsonElement representing null, return null.
            null or JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } => null,

            // When the parameter is an integer, return it as-is.
            long value => value,

            // When the parameter is a string value, try to parse it.
            string value => long.TryParse(value, NumberStyles.Integer,
                CultureInfo.InvariantCulture, out var result) ? result : null,

            // When the parameter is a JsonElement, try to convert it if it's of a supported type.
            JsonElement value => ConvertFromJsonElement(value),

#if SUPPORTS_JSON_NODES
            // When the parameter is a JsonValue wrapping a JsonElement,
            // apply the same logic as with direct JsonElement instances.
            JsonValue value when value.TryGetValue(out JsonElement element) => ConvertFromJsonElement(element),

            // When the parameter is a JsonValue wrapping an integer, return it as-is.
            JsonValue value when value.TryGetValue(out int  result) => result,
            JsonValue value when value.TryGetValue(out long result) => result,

            // When the parameter is a JsonValue wrapping a string, return it as-is.
            JsonValue value when value.TryGetValue(out string? text) =>
                long.TryParse(text, NumberStyles.Integer,
                    CultureInfo.InvariantCulture, out var result) ? result : null,

            // When the parameter is a JsonNode (e.g a JsonValue wrapping a non-primitive type),
            // serialize it to a JsonElement first to determine its actual JSON representation
            // and apply the same logic as with non-wrapped JsonElement instances.
            JsonNode value when JsonSerializer.SerializeToElement(value) is JsonElement element
                => ConvertFromJsonElement(element),
#endif
            // If the parameter is of a different type, return null to indicate the conversion failed.
            _ => null
        };

        static long? ConvertFromJsonElement(JsonElement element) => element.ValueKind switch
        {
            // When the parameter is a JsonElement representing a number, return it as-is.
            JsonValueKind.Number => element.TryGetInt64(out var result) ? result : null,

            // When the parameter is a JsonElement representing a string, try to parse it.
            JsonValueKind.String => long.TryParse(element.GetString(), NumberStyles.Integer,
                CultureInfo.InvariantCulture, out var result) ? result : null,

            _ => null
        };
    }

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a string.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator string?(OpenIddictParameter? parameter)
    {
        return parameter?.Value switch
        {
            // When the parameter is a null value or a JsonElement representing null, return null.
            null or JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } => null,

            // When the parameter is a string value, return it as-is.
            string value => value,

            // When the parameter is a boolean value, use its string representation.
            bool value => value ? "true" : "false",

            // When the parameter is an integer, use its string representation.
            long value => value.ToString(CultureInfo.InvariantCulture),

            // When the parameter is a JSON boolean value, use its string representation.
            JsonElement { ValueKind: JsonValueKind.True }  => "true",
            JsonElement { ValueKind: JsonValueKind.False } => "false",

            // When the parameter is a JsonElement, try to convert it if it's of a supported type.
            JsonElement value => ConvertFromJsonElement(value),

#if SUPPORTS_JSON_NODES
            // When the parameter is a JsonValue wrapping a JsonElement,
            // apply the same logic as with direct JsonElement instances.
            JsonValue value when value.TryGetValue(out JsonElement element) => ConvertFromJsonElement(element),

            // When the parameter is a JsonValue wrapping a string, return it as-is.
            JsonValue value when value.TryGetValue(out string? result) => result,

            // When the parameter is a JsonValue wrapping a boolean, return its representation.
            JsonValue value when value.TryGetValue(out bool result) => result ? "true" : "false",

            // When the parameter is a JsonValue wrapping a boolean, return its representation.
            JsonValue value when value.TryGetValue(out int result)  => result.ToString(CultureInfo.InvariantCulture),
            JsonValue value when value.TryGetValue(out long result) => result.ToString(CultureInfo.InvariantCulture),

            // When the parameter is a JsonNode (e.g a JsonValue wrapping a non-primitive type),
            // serialize it to a JsonElement first to determine its actual JSON representation
            // and apply the same logic as with non-wrapped JsonElement instances.
            JsonNode value when JsonSerializer.SerializeToElement(value) is JsonElement element
                => ConvertFromJsonElement(element),
#endif
            // If the parameter is of a different type, return null to indicate the conversion failed.
            _ => null
        };

        static string? ConvertFromJsonElement(JsonElement element) => element.ValueKind switch
        {
            // When the parameter is a JsonElement representing
            // a boolean, return its string representation.
            JsonValueKind.True  => "true",
            JsonValueKind.False => "false",

            // When the parameter is a JsonElement representing a
            // string or a number, return its string representation.
            JsonValueKind.String or JsonValueKind.Number => element.ToString(),

            _ => null
        };
    }

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to an array of strings.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator string?[]?(OpenIddictParameter? parameter)
    {
        return parameter?.Value switch
        {
            // When the parameter is a null value or a JsonElement representing null, return null.
            null or JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } => null,

            // When the parameter is already an array of strings, return it as-is.
            string?[] value => value,

            // When the parameter is a string value, return an array with a single entry.
            string value => [value],

            // When the parameter is a boolean value, return an array with its string representation.
            bool value => [value ? "true" : "false"],

            // When the parameter is an integer, return an array with its string representation.
            long value => [value.ToString(CultureInfo.InvariantCulture)],

            // When the parameter is a JSON boolean value, return an array with its string representation.
            JsonElement { ValueKind: JsonValueKind.True  } => ["true"],
            JsonElement { ValueKind: JsonValueKind.False } => ["false"],

            // When the parameter is a JsonElement, try to convert it if it's of a supported type.
            JsonElement value => ConvertFromJsonElement(value),

#if SUPPORTS_JSON_NODES
            // When the parameter is a JsonValue wrapping a JsonElement,
            // apply the same logic as with direct JsonElement instances.
            JsonValue value when value.TryGetValue(out JsonElement element) => ConvertFromJsonElement(element),

            // When the parameter is a JsonValue wrapping a string, return an array with a single entry.
            JsonValue value when value.TryGetValue(out string? result) => [result],

            // When the parameter is a JsonValue wrapping a boolean, return an array with its string representation.
            JsonValue value when value.TryGetValue(out bool result)
                => [result ? "true" : "false"],

            // When the parameter is a JsonValue wrapping an integer, return an array with its string representation.
            JsonValue value when value.TryGetValue(out int result)
                => [result.ToString(CultureInfo.InvariantCulture)],

            JsonValue value when value.TryGetValue(out long result)
                => [result.ToString(CultureInfo.InvariantCulture)],

            // When the parameter is a JsonNode (e.g a JsonValue wrapping a non-primitive type),
            // serialize it to a JsonElement first to determine its actual JSON representation
            // and apply the same logic as with non-wrapped JsonElement instances.
            JsonNode value when JsonSerializer.SerializeToElement(value) is JsonElement element
                => ConvertFromJsonElement(element),
#endif
            // If the parameter is of a different type, return null to indicate the conversion failed.
            _ => null
        };

        static string?[]? ConvertFromJsonElement(JsonElement element) => element.ValueKind switch
        {
            // When the parameter is a JsonElement representing a boolean,
            // return an 1-item array with its string representation.
            JsonValueKind.True  => ["true"],
            JsonValueKind.False => ["false"],

            // When the parameter is a JsonElement representing a string or a
            // number, return an 1-item array with its string representation.
            JsonValueKind.String or JsonValueKind.Number => [element.ToString()],

            // When the parameter is a JsonElement representing an array, return the elements as strings.
            JsonValueKind.Array => CreateArrayFromJsonElement(element),

            _ => null
        };

        static string?[]? CreateArrayFromJsonElement(JsonElement element)
        {
            var length = element.GetArrayLength();
            var array = new string?[length];

            for (var index = 0; index < length; index++)
            {
                var item = element[index];
                if (item.ValueKind is JsonValueKind.True)
                {
                    array[index] = "true";
                }

                else if (item.ValueKind is JsonValueKind.False)
                {
                    array[index] = "false";
                }

                else if (item.ValueKind is JsonValueKind.String or JsonValueKind.Number)
                {
                    array[index] = item.ToString();
                }

                // Always return a null array if one of the items is a not string, a number or a boolean.
                else
                {
                    return null;
                }
            }

            return array;
        }
    }

    /// <summary>
    /// Converts a boolean to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(bool value) => new(value);

    /// <summary>
    /// Converts a nullable boolean to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(bool? value) => new(value);

    /// <summary>
    /// Converts a <see cref="JsonElement"/> to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(JsonElement value) => new(value);

#if SUPPORTS_JSON_NODES
    /// <summary>
    /// Converts a <see cref="JsonNode"/> to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(JsonNode? value) => new(value);
#endif

    /// <summary>
    /// Converts a long integer to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(long value) => new(value);

    /// <summary>
    /// Converts a nullable long integer to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(long? value) => new(value);

    /// <summary>
    /// Converts a string to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(string? value) => new(value);

    /// <summary>
    /// Converts an array of strings to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(string?[]? value) => new(value);

    /// <summary>
    /// Determines whether a parameter is null or empty.
    /// </summary>
    /// <param name="parameter">The parameter.</param>
    /// <returns><see langword="true"/> if the parameter is null or empty, <see langword="false"/> otherwise.</returns>
    public static bool IsNullOrEmpty(OpenIddictParameter parameter)
    {
        return parameter.Value switch
        {
            null or JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } => true,

            string value    => value.Length is 0,
            string?[] value => value.Length is 0,

            JsonElement value => IsEmptyJsonElement(value),

#if SUPPORTS_JSON_NODES
            JsonArray  value => value.Count is 0,
            JsonObject value => value.Count is 0,

            JsonValue value when value.TryGetValue(out JsonElement element)
                => IsEmptyJsonElement(element),

            JsonValue value when value.TryGetValue(out string? result)
                => string.IsNullOrEmpty(result),

            JsonNode value when JsonSerializer.SerializeToElement(value) is JsonElement element
                => IsEmptyJsonElement(element),
#endif
            _ => false
        };

        static bool IsEmptyJsonElement(JsonElement element)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.String:
                    return string.IsNullOrEmpty(element.GetString());

                case JsonValueKind.Array:
                    return element.GetArrayLength() is 0;

                case JsonValueKind.Object:
                    using (var enumerator = element.EnumerateObject())
                    {
                        return !enumerator.MoveNext();
                    }

                default: return false;
            }
        }
    }
}

/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.Extensions.Primitives;

namespace OpenIddict.Abstractions;

/// <summary>
/// Provides extension methods to make <see cref="OpenIddictRequest"/>
/// and <see cref="OpenIddictResponse"/> easier to work with.
/// </summary>
public static class OpenIddictExtensions
{
    /// <summary>
    /// Extracts the authentication context class values from an <see cref="OpenIddictRequest"/>.
    /// </summary>
    /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
    public static ImmutableArray<string> GetAcrValues(this OpenIddictRequest request)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        return GetValues(request.AcrValues, Separators.Space);
    }

    /// <summary>
    /// Extracts the prompt values from an <see cref="OpenIddictRequest"/>.
    /// </summary>
    /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
    public static ImmutableArray<string> GetPromptValues(this OpenIddictRequest request)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        return GetValues(request.Prompt, Separators.Space);
    }

    /// <summary>
    /// Extracts the response types from an <see cref="OpenIddictRequest"/>.
    /// </summary>
    /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
    public static ImmutableArray<string> GetResponseTypes(this OpenIddictRequest request)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        return GetValues(request.ResponseType, Separators.Space);
    }

    /// <summary>
    /// Extracts the scopes from an <see cref="OpenIddictRequest"/>.
    /// </summary>
    /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
    public static ImmutableArray<string> GetScopes(this OpenIddictRequest request)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        return GetValues(request.Scope, Separators.Space);
    }

    /// <summary>
    /// Determines whether the requested authentication context class values contain the specified item.
    /// </summary>
    /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
    /// <param name="value">The component to look for in the parameter.</param>
    public static bool HasAcrValue(this OpenIddictRequest request, string value)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (string.IsNullOrEmpty(value))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0177), nameof(value));
        }

        return HasValue(request.AcrValues, value, Separators.Space);
    }

    /// <summary>
    /// Determines whether the requested prompt contains the specified value.
    /// </summary>
    /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
    /// <param name="prompt">The component to look for in the parameter.</param>
    public static bool HasPromptValue(this OpenIddictRequest request, string prompt)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (string.IsNullOrEmpty(prompt))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0178), nameof(prompt));
        }

        return HasValue(request.Prompt, prompt, Separators.Space);
    }

    /// <summary>
    /// Determines whether the requested response type contains the specified value.
    /// </summary>
    /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
    /// <param name="type">The component to look for in the parameter.</param>
    public static bool HasResponseType(this OpenIddictRequest request, string type)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0179), nameof(type));
        }

        return HasValue(request.ResponseType, type, Separators.Space);
    }

    /// <summary>
    /// Determines whether the requested scope contains the specified value.
    /// </summary>
    /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
    /// <param name="scope">The component to look for in the parameter.</param>
    public static bool HasScope(this OpenIddictRequest request, string scope)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (string.IsNullOrEmpty(scope))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0180), nameof(scope));
        }

        return HasValue(request.Scope, scope, Separators.Space);
    }

    /// <summary>
    /// Determines whether the "response_type" parameter corresponds to the "none" response type.
    /// See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none for more information.
    /// </summary>
    /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
    /// <returns><see langword="true"/> if the request is a response_type=none request, <see langword="false"/> otherwise.</returns>
    public static bool IsNoneFlow(this OpenIddictRequest request)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (string.IsNullOrEmpty(request.ResponseType))
        {
            return false;
        }

        var segment = Trim(new StringSegment(request.ResponseType), Separators.Space);
        if (!segment.HasValue || segment.Length is 0)
        {
            return false;
        }

        return segment.Equals(ResponseTypes.None, StringComparison.Ordinal);
    }

    /// <summary>
    /// Determines whether the "response_type" parameter corresponds to the authorization code flow.
    /// See http://tools.ietf.org/html/rfc6749#section-4.1.1 for more information.
    /// </summary>
    /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
    /// <returns><see langword="true"/> if the request is a code flow request, <see langword="false"/> otherwise.</returns>
    public static bool IsAuthorizationCodeFlow(this OpenIddictRequest request)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (string.IsNullOrEmpty(request.ResponseType))
        {
            return false;
        }

        var segment = Trim(new StringSegment(request.ResponseType), Separators.Space);
        if (!segment.HasValue || segment.Length is 0)
        {
            return false;
        }

        return segment.Equals(ResponseTypes.Code, StringComparison.Ordinal);
    }

    /// <summary>
    /// Determines whether the "response_type" parameter corresponds to the implicit flow.
    /// See http://tools.ietf.org/html/rfc6749#section-4.2.1 and
    /// http://openid.net/specs/openid-connect-core-1_0.html for more information
    /// </summary>
    /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
    /// <returns><see langword="true"/> if the request is an implicit flow request, <see langword="false"/> otherwise.</returns>
    public static bool IsImplicitFlow(this OpenIddictRequest request)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (string.IsNullOrEmpty(request.ResponseType))
        {
            return false;
        }

        var flags = /* none: */ 0x00;

        foreach (var element in new StringTokenizer(request.ResponseType, Separators.Space))
        {
            var segment = Trim(element, Separators.Space);
            if (!segment.HasValue || segment.Length is 0)
            {
                continue;
            }

            if (segment.Equals(ResponseTypes.IdToken, StringComparison.Ordinal))
            {
                flags |= /* id_token: */ 0x01;

                continue;
            }

            // Note: though the OIDC core specs does not include the OAuth 2.0-inherited response_type=token,
            // it is considered as a valid response_type for the implicit flow for backward compatibility.
            else if (segment.Equals(ResponseTypes.Token, StringComparison.Ordinal))
            {
                flags |= /* token */ 0x02;

                continue;
            }

            // Always return false if the response_type item
            // is not a valid component for the implicit flow.
            return false;
        }

        // Return true if the response_type parameter contains "id_token" or "token".
        return (flags & /* id_token: */ 0x01) == 0x01 || (flags & /* token: */ 0x02) == 0x02;
    }

    /// <summary>
    /// Determines whether the "response_type" parameter corresponds to the hybrid flow.
    /// See http://tools.ietf.org/html/rfc6749#section-4.2.1 and
    /// http://openid.net/specs/openid-connect-core-1_0.html for more information.
    /// </summary>
    /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
    /// <returns><see langword="true"/> if the request is an hybrid flow request, <see langword="false"/> otherwise.</returns>
    public static bool IsHybridFlow(this OpenIddictRequest request)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (string.IsNullOrEmpty(request.ResponseType))
        {
            return false;
        }

        var flags = /* none */ 0x00;

        foreach (var element in new StringTokenizer(request.ResponseType, Separators.Space))
        {
            var segment = Trim(element, Separators.Space);
            if (!segment.HasValue || segment.Length is 0)
            {
                continue;
            }

            if (segment.Equals(ResponseTypes.Code, StringComparison.Ordinal))
            {
                flags |= /* code: */ 0x01;

                continue;
            }

            else if (segment.Equals(ResponseTypes.IdToken, StringComparison.Ordinal))
            {
                flags |= /* id_token: */ 0x02;

                continue;
            }

            else if (segment.Equals(ResponseTypes.Token, StringComparison.Ordinal))
            {
                flags |= /* token: */ 0x04;

                continue;
            }

            // Always return false if the response_type item
            // is not a valid component for the hybrid flow.
            return false;
        }

        // Return false if the response_type parameter doesn't contain "code".
        if ((flags & /* code: */ 0x01) != 0x01)
        {
            return false;
        }

        // Return true if the response_type parameter contains "id_token" or "token".
        return (flags & /* id_token: */ 0x02) == 0x02 || (flags & /* token: */ 0x04) == 0x04;
    }

    /// <summary>
    /// Determines whether the "response_mode" parameter corresponds to the fragment response mode.
    /// See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html for more information.
    /// </summary>
    /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
    /// <returns>
    /// <see langword="true"/> if the request specified the fragment response mode or if
    /// it's the default value for the requested flow, <see langword="false"/> otherwise.
    /// </returns>
    public static bool IsFragmentResponseMode(this OpenIddictRequest request)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (string.Equals(request.ResponseMode, ResponseModes.Fragment, StringComparison.Ordinal))
        {
            return true;
        }

        // Don't guess the response_mode value
        // if an explicit value has been provided.
        if (!string.IsNullOrEmpty(request.ResponseMode))
        {
            return false;
        }

        // Both the implicit and the hybrid flows
        // use response_mode=fragment by default.
        return request.IsImplicitFlow() || request.IsHybridFlow();
    }

    /// <summary>
    /// Determines whether the "response_mode" parameter corresponds to the query response mode.
    /// See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html for more information.
    /// </summary>
    /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
    /// <returns>
    /// <see langword="true"/> if the request specified the query response mode or if
    /// it's the default value for the requested flow, <see langword="false"/> otherwise.
    /// </returns>
    public static bool IsQueryResponseMode(this OpenIddictRequest request)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (string.Equals(request.ResponseMode, ResponseModes.Query, StringComparison.Ordinal))
        {
            return true;
        }

        // Don't guess the response_mode value
        // if an explicit value has been provided.
        if (!string.IsNullOrEmpty(request.ResponseMode))
        {
            return false;
        }

        // Code flow and "response_type=none" use response_mode=query by default.
        return request.IsAuthorizationCodeFlow() || request.IsNoneFlow();
    }

    /// <summary>
    /// Determines whether the "response_mode" parameter corresponds to the form post response mode.
    /// See http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html for more information.
    /// </summary>
    /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
    /// <returns>
    /// <see langword="true"/> if the request specified the form post response mode or if
    /// it's the default value for the requested flow, <see langword="false"/> otherwise.
    /// </returns>
    public static bool IsFormPostResponseMode(this OpenIddictRequest request)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        return string.Equals(request.ResponseMode, ResponseModes.FormPost, StringComparison.Ordinal);
    }

    /// <summary>
    /// Determines whether the "grant_type" parameter corresponds to the authorization code grant.
    /// See http://tools.ietf.org/html/rfc6749#section-4.1.3 for more information.
    /// </summary>
    /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
    /// <returns><see langword="true"/> if the request is a code grant request, <see langword="false"/> otherwise.</returns>
    public static bool IsAuthorizationCodeGrantType(this OpenIddictRequest request)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        return string.Equals(request.GrantType, GrantTypes.AuthorizationCode, StringComparison.Ordinal);
    }

    /// <summary>
    /// Determines whether the "grant_type" parameter corresponds to the client credentials grant.
    /// See http://tools.ietf.org/html/rfc6749#section-4.4.2 for more information.
    /// </summary>
    /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
    /// <returns><see langword="true"/> if the request is a client credentials grant request, <see langword="false"/> otherwise.</returns>
    public static bool IsClientCredentialsGrantType(this OpenIddictRequest request)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        return string.Equals(request.GrantType, GrantTypes.ClientCredentials, StringComparison.Ordinal);
    }

    /// <summary>
    /// Determines whether the "grant_type" parameter corresponds to the device code grant.
    /// See https://tools.ietf.org/html/rfc8628 for more information.
    /// </summary>
    /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
    /// <returns><see langword="true"/> if the request is a device code grant request, <see langword="false"/> otherwise.</returns>
    public static bool IsDeviceCodeGrantType(this OpenIddictRequest request)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        return string.Equals(request.GrantType, GrantTypes.DeviceCode, StringComparison.Ordinal);
    }

    /// <summary>
    /// Determines whether the "grant_type" parameter corresponds to the password grant.
    /// See http://tools.ietf.org/html/rfc6749#section-4.3.2 for more information.
    /// </summary>
    /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
    /// <returns><see langword="true"/> if the request is a password grant request, <see langword="false"/> otherwise.</returns>
    public static bool IsPasswordGrantType(this OpenIddictRequest request)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        return string.Equals(request.GrantType, GrantTypes.Password, StringComparison.Ordinal);
    }

    /// <summary>
    /// Determines whether the "grant_type" parameter corresponds to the refresh token grant.
    /// See http://tools.ietf.org/html/rfc6749#section-6 for more information.
    /// </summary>
    /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
    /// <returns><see langword="true"/> if the request is a refresh token grant request, <see langword="false"/> otherwise.</returns>
    public static bool IsRefreshTokenGrantType(this OpenIddictRequest request)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        return string.Equals(request.GrantType, GrantTypes.RefreshToken, StringComparison.Ordinal);
    }

    /// <summary>
    /// Gets the destinations associated with a claim.
    /// </summary>
    /// <param name="claim">The <see cref="Claim"/> instance.</param>
    /// <returns>The destinations associated with the claim.</returns>
    public static ImmutableArray<string> GetDestinations(this Claim claim)
    {
        if (claim is null)
        {
            throw new ArgumentNullException(nameof(claim));
        }

        claim.Properties.TryGetValue(Properties.Destinations, out string? destinations);

        if (string.IsNullOrEmpty(destinations))
        {
            return ImmutableArray<string>.Empty;
        }

        using var document = JsonDocument.Parse(destinations);
        var builder = ImmutableArray.CreateBuilder<string>(document.RootElement.GetArrayLength());

        foreach (var element in document.RootElement.EnumerateArray())
        {
            var value = element.GetString();
            if (string.IsNullOrEmpty(value) || builder.Contains(value, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            builder.Add(value);
        }

        return builder.ToImmutable();
    }

    /// <summary>
    /// Determines whether the given claim contains the required destination.
    /// </summary>
    /// <param name="claim">The <see cref="Claim"/> instance.</param>
    /// <param name="destination">The required destination.</param>
    public static bool HasDestination(this Claim claim, string destination)
    {
        if (claim is null)
        {
            throw new ArgumentNullException(nameof(claim));
        }

        if (string.IsNullOrEmpty(destination))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0181), nameof(destination));
        }

        claim.Properties.TryGetValue(Properties.Destinations, out string? destinations);

        if (string.IsNullOrEmpty(destinations))
        {
            return false;
        }

        using var document = JsonDocument.Parse(destinations);

        foreach (var element in document.RootElement.EnumerateArray())
        {
            var value = element.GetString();
            if (string.Equals(value, destination, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Adds specific destinations to a claim.
    /// </summary>
    /// <param name="claim">The <see cref="Claim"/> instance.</param>
    /// <param name="destinations">The destinations.</param>
    public static Claim SetDestinations(this Claim claim, ImmutableArray<string> destinations)
    {
        if (claim is null)
        {
            throw new ArgumentNullException(nameof(claim));
        }

        if (destinations.IsDefaultOrEmpty)
        {
            claim.Properties.Remove(Properties.Destinations);

            return claim;
        }

        if (destinations.Any(string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0182), nameof(destinations));
        }

        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            Indented = false
        });

        writer.WriteStartArray();

        foreach (var destination in destinations.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            writer.WriteStringValue(destination);
        }

        writer.WriteEndArray();
        writer.Flush();

        claim.Properties[Properties.Destinations] = Encoding.UTF8.GetString(stream.ToArray());

        return claim;
    }

    /// <summary>
    /// Adds specific destinations to a claim.
    /// </summary>
    /// <param name="claim">The <see cref="Claim"/> instance.</param>
    /// <param name="destinations">The destinations.</param>
    public static Claim SetDestinations(this Claim claim, IEnumerable<string>? destinations)
        => claim.SetDestinations(destinations?.ToImmutableArray() ?? ImmutableArray<string>.Empty);

    /// <summary>
    /// Adds specific destinations to a claim.
    /// </summary>
    /// <param name="claim">The <see cref="Claim"/> instance.</param>
    /// <param name="destinations">The destinations.</param>
    public static Claim SetDestinations(this Claim claim, params string[]? destinations)
        => claim.SetDestinations(destinations?.ToImmutableArray() ?? ImmutableArray<string>.Empty);

    /// <summary>
    /// Gets the destinations associated with all the claims of the given identity.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <returns>The destinations, returned as a flattened dictionary.</returns>
    public static ImmutableDictionary<string, string[]> GetDestinations(this ClaimsIdentity identity)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        var builder = ImmutableDictionary.CreateBuilder<string, string[]>(StringComparer.Ordinal);

        foreach (var group in identity.Claims.GroupBy(claim => claim.Type))
        {
            var claims = group.ToList();

            var destinations = new HashSet<string>(claims[0].GetDestinations(), StringComparer.OrdinalIgnoreCase);
            if (destinations.Count is not 0)
            {
                // Ensure the other claims of the same type use the same exact destinations.
                for (var index = 0; index < claims.Count; index++)
                {
                    if (!destinations.SetEquals(claims[index].GetDestinations()))
                    {
                        throw new InvalidOperationException(SR.FormatID0183(group.Key));
                    }
                }

                builder.Add(group.Key, [.. destinations]);
            }
        }

        return builder.ToImmutable();
    }

    /// <summary>
    /// Gets the destinations associated with all the claims of the given principal.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <returns>The destinations, returned as a flattened dictionary.</returns>
    public static ImmutableDictionary<string, string[]> GetDestinations(this ClaimsPrincipal principal)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        var builder = ImmutableDictionary.CreateBuilder<string, string[]>(StringComparer.Ordinal);

        foreach (var group in principal.Claims.GroupBy(claim => claim.Type))
        {
            var claims = group.ToList();

            var destinations = new HashSet<string>(claims[0].GetDestinations(), StringComparer.OrdinalIgnoreCase);
            if (destinations.Count is not 0)
            {
                // Ensure the other claims of the same type use the same exact destinations.
                for (var index = 0; index < claims.Count; index++)
                {
                    if (!destinations.SetEquals(claims[index].GetDestinations()))
                    {
                        throw new InvalidOperationException(SR.FormatID0183(group.Key));
                    }
                }

                builder.Add(group.Key, [.. destinations]);
            }
        }

        return builder.ToImmutable();
    }

    /// <summary>
    /// Sets the destinations associated with all the claims of the given identity.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="destinations">The destinations, as a flattened dictionary.</param>
    /// <returns>The identity.</returns>
    public static ClaimsIdentity SetDestinations(this ClaimsIdentity identity, ImmutableDictionary<string, string[]> destinations)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (destinations is null)
        {
            throw new ArgumentNullException(nameof(destinations));
        }

        foreach (var destination in destinations)
        {
            foreach (var claim in identity.Claims.Where(claim => claim.Type == destination.Key))
            {
                claim.SetDestinations(destination.Value);
            }
        }

        return identity;
    }

    /// <summary>
    /// Sets the destinations associated with all the claims of the given principal.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="destinations">The destinations, as a flattened dictionary.</param>
    /// <returns>The principal.</returns>
    public static ClaimsPrincipal SetDestinations(this ClaimsPrincipal principal, ImmutableDictionary<string, string[]> destinations)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (destinations is null)
        {
            throw new ArgumentNullException(nameof(destinations));
        }

        foreach (var destination in destinations)
        {
            foreach (var claim in principal.Claims.Where(claim => claim.Type == destination.Key))
            {
                claim.SetDestinations(destination.Value);
            }
        }

        return principal;
    }

    /// <summary>
    /// Sets the destinations associated with all the claims of the given identity.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="selector">The destinations selector delegate.</param>
    /// <returns>The identity.</returns>
    public static ClaimsIdentity SetDestinations(this ClaimsIdentity identity, Func<Claim, IEnumerable<string>> selector)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (selector is null)
        {
            throw new ArgumentNullException(nameof(selector));
        }

        foreach (var claim in identity.Claims)
        {
            claim.SetDestinations(selector(claim));
        }

        return identity;
    }

    /// <summary>
    /// Sets the destinations associated with all the claims of the given principal.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="selector">The destinations selector delegate.</param>
    /// <returns>The principal.</returns>
    public static ClaimsPrincipal SetDestinations(this ClaimsPrincipal principal, Func<Claim, IEnumerable<string>> selector)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (selector is null)
        {
            throw new ArgumentNullException(nameof(selector));
        }

        foreach (var claim in principal.Claims)
        {
            claim.SetDestinations(selector(claim));
        }

        return principal;
    }

    /// <summary>
    /// Clones an identity by filtering its claims and the claims of its actor, recursively.
    /// </summary>
    /// <param name="identity">The <see cref="ClaimsIdentity"/> instance to filter.</param>
    /// <param name="filter">
    /// The delegate filtering the claims: return <see langword="true"/>
    /// to accept the claim, <see langword="false"/> to remove it.
    /// </param>
    public static ClaimsIdentity Clone(this ClaimsIdentity identity, Func<Claim, bool> filter)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (filter is null)
        {
            throw new ArgumentNullException(nameof(filter));
        }

        var clone = identity.Clone();

        // Note: make sure to call ToList() to avoid modifying
        // the initial collection iterated by ClaimsIdentity.Claims.
        foreach (var claim in clone.Claims.ToList())
        {
            if (!filter(claim))
            {
                clone.RemoveClaim(claim);
            }
        }

        if (clone.Actor is not null)
        {
            clone.Actor = clone.Actor.Clone(filter);
        }

        return clone;
    }

    /// <summary>
    /// Clones a principal by filtering its identities.
    /// </summary>
    /// <param name="principal">The <see cref="ClaimsPrincipal"/> instance to filter.</param>
    /// <param name="filter">
    /// The delegate filtering the claims: return <see langword="true"/>
    /// to accept the claim, <see langword="false"/> to remove it.
    /// </param>
    public static ClaimsPrincipal Clone(this ClaimsPrincipal principal, Func<Claim, bool> filter)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (filter is null)
        {
            throw new ArgumentNullException(nameof(filter));
        }

        var clone = new ClaimsPrincipal();

        foreach (var identity in principal.Identities)
        {
            clone.AddIdentity(identity.Clone(filter));
        }

        return clone;
    }

    /// <summary>
    /// Adds a claim to a given identity.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    public static ClaimsIdentity AddClaim(this ClaimsIdentity identity, string type, string value)
        => identity.AddClaim(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Adds a claim to a given principal.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    public static ClaimsPrincipal AddClaim(this ClaimsPrincipal principal, string type, string value)
        => principal.AddClaim(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Adds a claim to a given identity.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <param name="issuer">The issuer associated with the claim.</param>
    public static ClaimsIdentity AddClaim(this ClaimsIdentity identity, string type, string value, string issuer)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        identity.AddClaim(new Claim(type, value, ClaimValueTypes.String, issuer, issuer, identity));
        return identity;
    }

    /// <summary>
    /// Adds a claim to a given principal.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <param name="issuer">The issuer associated with the claim.</param>
    public static ClaimsPrincipal AddClaim(this ClaimsPrincipal principal, string type, string value, string issuer)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (principal.Identity is not ClaimsIdentity identity)
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0286), nameof(principal));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        identity.AddClaim(type, value, issuer);
        return principal;
    }

    /// <summary>
    /// Adds a claim to a given identity.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    public static ClaimsIdentity AddClaim(this ClaimsIdentity identity, string type, bool value)
        => identity.AddClaim(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Adds a claim to a given principal.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    public static ClaimsPrincipal AddClaim(this ClaimsPrincipal principal, string type, bool value)
        => principal.AddClaim(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Adds a claim to a given identity.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <param name="issuer">The issuer associated with the claim.</param>
    public static ClaimsIdentity AddClaim(this ClaimsIdentity identity, string type, bool value, string issuer)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        identity.AddClaim(new Claim(type, value.ToString(), ClaimValueTypes.Boolean, issuer, issuer, identity));
        return identity;
    }

    /// <summary>
    /// Adds a claim to a given principal.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <param name="issuer">The issuer associated with the claim.</param>
    public static ClaimsPrincipal AddClaim(this ClaimsPrincipal principal, string type, bool value, string issuer)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (principal.Identity is not ClaimsIdentity identity)
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0286), nameof(principal));
        }

        identity.AddClaim(type, value, issuer);
        return principal;
    }

    /// <summary>
    /// Adds a claim to a given identity.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    public static ClaimsIdentity AddClaim(this ClaimsIdentity identity, string type, long value)
        => identity.AddClaim(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Adds a claim to a given principal.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    public static ClaimsPrincipal AddClaim(this ClaimsPrincipal principal, string type, long value)
        => principal.AddClaim(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Adds a claim to a given identity.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <param name="issuer">The issuer associated with the claim.</param>
    public static ClaimsIdentity AddClaim(this ClaimsIdentity identity, string type, long value, string issuer)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        identity.AddClaim(new Claim(type, value.ToString(CultureInfo.InvariantCulture),
            ClaimValueTypes.Integer64, issuer, issuer, identity));
        return identity;
    }

    /// <summary>
    /// Adds a claim to a given principal.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <param name="issuer">The issuer associated with the claim.</param>
    public static ClaimsPrincipal AddClaim(this ClaimsPrincipal principal, string type, long value, string issuer)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (principal.Identity is not ClaimsIdentity identity)
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0286), nameof(principal));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        identity.AddClaim(type, value, issuer);
        return principal;
    }

    /// <summary>
    /// Adds a claim to a given identity.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    public static ClaimsIdentity AddClaim(this ClaimsIdentity identity, string type, JsonElement value)
        => identity.AddClaim(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Adds a claim to a given principal.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    public static ClaimsPrincipal AddClaim(this ClaimsPrincipal principal, string type, JsonElement value)
        => principal.AddClaim(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Adds a claim to a given identity.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <param name="issuer">The issuer associated with the claim.</param>
    public static ClaimsIdentity AddClaim(this ClaimsIdentity identity, string type, JsonElement value, string issuer)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        if (value.ValueKind is JsonValueKind.Array)
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0185), nameof(value));
        }

        identity.AddClaim(new Claim(
            type          : type,
            value         : value.ToString()!,
            valueType     : GetClaimValueType(value),
            issuer        : issuer,
            originalIssuer: issuer,
            subject       : identity));

        return identity;
    }

    /// <summary>
    /// Adds a claim to a given principal.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <param name="issuer">The issuer associated with the claim.</param>
    public static ClaimsPrincipal AddClaim(this ClaimsPrincipal principal, string type, JsonElement value, string issuer)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (principal.Identity is not ClaimsIdentity identity)
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0286), nameof(principal));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        identity.AddClaim(type, value, issuer);

        return principal;
    }

    /// <summary>
    /// Adds a claim to a given identity.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    public static ClaimsIdentity AddClaim(this ClaimsIdentity identity,
        string type, IDictionary<string, string?> value)
        => identity.AddClaim(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Adds a claim to a given principal.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    public static ClaimsPrincipal AddClaim(this ClaimsPrincipal principal,
        string type, IDictionary<string, string?> value)
        => principal.AddClaim(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Adds a claim to a given identity.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <param name="issuer">The issuer associated with the claim.</param>
    public static ClaimsIdentity AddClaim(this ClaimsIdentity identity, string type,
        IDictionary<string, string?> value, string issuer)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            Indented = false
        });

        writer.WriteStartObject();

        foreach (var property in value)
        {
            writer.WritePropertyName(property.Key);
            writer.WriteStringValue(property.Value);
        }

        writer.WriteEndObject();
        writer.Flush();

        identity.AddClaim(new Claim(
            type          : type,
            value         : Encoding.UTF8.GetString(stream.ToArray()),
            valueType     : "JSON",
            issuer        : issuer,
            originalIssuer: issuer,
            subject       : identity));

        return identity;
    }

    /// <summary>
    /// Adds a claim to a given principal.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <param name="issuer">The issuer associated with the claim.</param>
    public static ClaimsPrincipal AddClaim(this ClaimsPrincipal principal, string type,
        IDictionary<string, string?> value, string issuer)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (principal.Identity is not ClaimsIdentity identity)
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0286), nameof(principal));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        identity.AddClaim(type, value, issuer);

        return principal;
    }

    /// <summary>
    /// Adds claims to a given identity.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claims.</param>
    /// <param name="values">The values associated with the claims.</param>
    public static ClaimsIdentity AddClaims(this ClaimsIdentity identity, string type, ImmutableArray<string> values)
        => identity.AddClaims(type, values, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Adds claims to a given principal.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claims.</param>
    /// <param name="values">The values associated with the claims.</param>
    public static ClaimsPrincipal AddClaims(this ClaimsPrincipal principal, string type, ImmutableArray<string> values)
        => principal.AddClaims(type, values, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Adds claims to a given identity.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claims.</param>
    /// <param name="values">The values associated with the claims.</param>
    /// <param name="issuer">The issuer associated with the claims.</param>
    public static ClaimsIdentity AddClaims(this ClaimsIdentity identity, string type, ImmutableArray<string> values, string issuer)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        var set = new HashSet<string>(StringComparer.Ordinal);

        for (var index = 0; index < values.Length; index++)
        {
            var item = values[index];
            if (set.Add(item))
            {
                identity.AddClaim(new Claim(
                    type          : type,
                    value         : item,
                    valueType     : ClaimValueTypes.String,
                    issuer        : issuer,
                    originalIssuer: issuer,
                    subject       : identity));
            }
        }

        return identity;
    }

    /// <summary>
    /// Adds claims to a given principal.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claims.</param>
    /// <param name="values">The values associated with the claims.</param>
    /// <param name="issuer">The issuer associated with the claims.</param>
    public static ClaimsPrincipal AddClaims(this ClaimsPrincipal principal,
        string type, ImmutableArray<string> values, string issuer)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (principal.Identity is not ClaimsIdentity identity)
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0286), nameof(principal));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        identity.AddClaims(type, values, issuer);

        return principal;
    }

    /// <summary>
    /// Adds claims to a given identity.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claims.</param>
    /// <param name="value">The value associated with the claims.</param>
    public static ClaimsIdentity AddClaims(this ClaimsIdentity identity, string type, JsonElement value)
        => identity.AddClaims(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Adds claims to a given principal.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claims.</param>
    /// <param name="value">The value associated with the claims.</param>
    public static ClaimsPrincipal AddClaims(this ClaimsPrincipal principal, string type, JsonElement value)
        => principal.AddClaims(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Adds claims to a given identity.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claims.</param>
    /// <param name="value">The value associated with the claims.</param>
    /// <param name="issuer">The issuer associated with the claims.</param>
    public static ClaimsIdentity AddClaims(this ClaimsIdentity identity, string type, JsonElement value, string issuer)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        if (value.ValueKind is not JsonValueKind.Array)
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0185), nameof(value));
        }

        var set = new HashSet<string>(StringComparer.Ordinal);

        foreach (var element in value.EnumerateArray())
        {
            var item = element.ToString()!;
            if (set.Add(item))
            {
                identity.AddClaim(new Claim(
                    type          : type,
                    value         : item,
                    valueType     : GetClaimValueType(element),
                    issuer        : issuer,
                    originalIssuer: issuer,
                    subject       : identity));
            }
        }

        return identity;
    }

    /// <summary>
    /// Adds claims to a given principal.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claims.</param>
    /// <param name="value">The value associated with the claims.</param>
    /// <param name="issuer">The issuer associated with the claims.</param>
    public static ClaimsPrincipal AddClaims(this ClaimsPrincipal principal, string type, JsonElement value, string issuer)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (principal.Identity is not ClaimsIdentity identity)
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0286), nameof(principal));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        if (value.ValueKind is not JsonValueKind.Array)
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0185), nameof(value));
        }

        identity.AddClaims(type, value, issuer);

        return principal;
    }

    /// <summary>
    /// Gets the unique claim value corresponding to the given type.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <exception cref="InvalidOperationException">
    /// Multiple claims using the same <paramref name="type"/> are present in the identity.
    /// </exception>
    /// <returns>The claim value.</returns>
    public static string? GetClaim(this ClaimsIdentity identity, string type)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        var claims = identity.FindAll(type);
        if (claims is IList<Claim> list)
        {
            return list switch
            {
                [Claim claim] => claim.Value,
                [           ] => null,
                [     ..    ] => throw new InvalidOperationException(SR.GetResourceString(SR.ID0423))
            };
        }

        else
        {
            using var enumerator = claims.GetEnumerator();
            while (enumerator.MoveNext())
            {
                var claim = enumerator.Current;
                if (!enumerator.MoveNext())
                {
                    return claim.Value;
                }

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0423));
            }

            return null;
        }
    }

    /// <summary>
    /// Gets the unique claim value corresponding to the given type.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <exception cref="InvalidOperationException">
    /// Multiple claims using the same <paramref name="type"/> are present in the principal.
    /// </exception>
    /// <returns>The claim value.</returns>
    public static string? GetClaim(this ClaimsPrincipal principal, string type)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        var claims = principal.FindAll(type);
        if (claims is IList<Claim> list)
        {
            return list switch
            {
                [Claim claim] => claim.Value,
                [           ] => null,
                [     ..    ] => throw new InvalidOperationException(SR.GetResourceString(SR.ID0423))
            };
        }

        else
        {
            using var enumerator = claims.GetEnumerator();
            while (enumerator.MoveNext())
            {
                var claim = enumerator.Current;
                if (!enumerator.MoveNext())
                {
                    return claim.Value;
                }

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0423));
            }

            return null;
        }
    }

    /// <summary>
    /// Gets all the claim values corresponding to the given type.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="type">The type associated with the claims.</param>
    /// <returns>The claim values.</returns>
    public static ImmutableArray<string> GetClaims(this ClaimsIdentity identity, string type)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        var builder = ImmutableArray.CreateBuilder<string>();

        foreach (var claim in identity.FindAll(type))
        {
            // If the claim uses the special JSON_ARRAY claim value type, parse it to extract its individual
            // values. When the individual values are not strings, their string representation is returned.
            if (claim.ValueType is "JSON_ARRAY")
            {
                var element = JsonSerializer.Deserialize<JsonElement>(claim.Value);
                if (element.ValueKind is not JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var item in element.EnumerateArray())
                {
                    var value = item.ToString();
                    if (!builder.Contains(value))
                    {
                        builder.Add(value);
                    }
                }
            }

            else if (!builder.Contains(claim.Value))
            {
                builder.Add(claim.Value);
            }
        }

        return builder.ToImmutable();
    }

    /// <summary>
    /// Gets all the claim values corresponding to the given type.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="type">The type associated with the claims.</param>
    /// <returns>The claim values.</returns>
    public static ImmutableArray<string> GetClaims(this ClaimsPrincipal principal, string type)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        var builder = ImmutableArray.CreateBuilder<string>();

        foreach (var claim in principal.FindAll(type))
        {
            // If the claim uses the special JSON_ARRAY claim value type, parse it to extract its individual
            // values. When the individual values are not strings, their string representation is returned.
            if (claim.ValueType is "JSON_ARRAY")
            {
                var element = JsonSerializer.Deserialize<JsonElement>(claim.Value);
                if (element.ValueKind is not JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var item in element.EnumerateArray())
                {
                    var value = item.ToString();
                    if (!builder.Contains(value))
                    {
                        builder.Add(value);
                    }
                }
            }

            else if (!builder.Contains(claim.Value))
            {
                builder.Add(claim.Value);
            }
        }

        return builder.ToImmutable();
    }

    /// <summary>
    /// Determines whether the claims identity contains at least one claim of the specified type.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="type">The claim type.</param>
    /// <returns><see langword="true"/> if the identity contains at least one claim of the specified type.</returns>
    public static bool HasClaim(this ClaimsIdentity identity, string type)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        return identity.FindAll(type).Any();
    }

    /// <summary>
    /// Determines whether the claims principal contains at least one claim of the specified type.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="type">The claim type.</param>
    /// <returns><see langword="true"/> if the principal contains at least one claim of the specified type.</returns>
    public static bool HasClaim(this ClaimsPrincipal principal, string type)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        return principal.FindAll(type).Any();
    }

    /// <summary>
    /// Removes all the claims corresponding to the given type.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claims.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity RemoveClaims(this ClaimsIdentity identity, string type)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        foreach (var claim in identity.FindAll(type).ToList())
        {
            identity.RemoveClaim(claim);
        }

        return identity;
    }

    /// <summary>
    /// Removes all the claims corresponding to the given type.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claims.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsPrincipal RemoveClaims(this ClaimsPrincipal principal, string type)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        foreach (var identity in principal.Identities)
        {
            foreach (var claim in identity.FindAll(type).ToList())
            {
                identity.RemoveClaim(claim);
            }
        }

        return principal;
    }

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetClaim(this ClaimsIdentity identity, string type, string? value)
        => identity.SetClaim(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsPrincipal SetClaim(this ClaimsPrincipal principal, string type, string? value)
        => principal.SetClaim(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <param name="issuer">The issuer associated with the claim.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetClaim(this ClaimsIdentity identity, string type, string? value, string issuer)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        identity.RemoveClaims(type);

        if (!string.IsNullOrEmpty(value))
        {
            identity.AddClaim(type, value, issuer);
        }

        return identity;
    }

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <param name="issuer">The issuer associated with the claim.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsPrincipal SetClaim(this ClaimsPrincipal principal, string type, string? value, string issuer)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        principal.RemoveClaims(type);

        if (!string.IsNullOrEmpty(value))
        {
            principal.AddClaim(type, value, issuer);
        }

        return principal;
    }

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetClaim(this ClaimsIdentity identity, string type, bool? value)
        => identity.SetClaim(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsPrincipal SetClaim(this ClaimsPrincipal principal, string type, bool? value)
        => principal.SetClaim(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <param name="issuer">The issuer associated with the claim.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetClaim(this ClaimsIdentity identity, string type, bool? value, string issuer)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        identity.RemoveClaims(type);

        if (value is not null)
        {
            identity.AddClaim(type, value.GetValueOrDefault(), issuer);
        }

        return identity;
    }

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <param name="issuer">The issuer associated with the claim.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsPrincipal SetClaim(this ClaimsPrincipal principal, string type, bool? value, string issuer)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        principal.RemoveClaims(type);

        if (value is not null)
        {
            principal.AddClaim(type, value.GetValueOrDefault(), issuer);
        }

        return principal;
    }

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetClaim(this ClaimsIdentity identity, string type, long? value)
        => identity.SetClaim(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsPrincipal SetClaim(this ClaimsPrincipal principal, string type, long? value)
        => principal.SetClaim(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <param name="issuer">The issuer associated with the claim.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetClaim(this ClaimsIdentity identity, string type, long? value, string issuer)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        identity.RemoveClaims(type);

        if (value is not null)
        {
            identity.AddClaim(type, value.GetValueOrDefault(), issuer);
        }

        return identity;
    }

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <param name="issuer">The issuer associated with the claim.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsPrincipal SetClaim(this ClaimsPrincipal principal, string type, long? value, string issuer)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        principal.RemoveClaims(type);

        if (value is not null)
        {
            principal.AddClaim(type, value.GetValueOrDefault(), issuer);
        }

        return principal;
    }

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetClaim(this ClaimsIdentity identity, string type, JsonElement value)
        => identity.SetClaim(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsPrincipal SetClaim(this ClaimsPrincipal principal, string type, JsonElement value)
        => principal.SetClaim(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <param name="issuer">The issuer associated with the claim.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetClaim(this ClaimsIdentity identity, string type, JsonElement value, string issuer)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        identity.RemoveClaims(type);

        if (!IsEmptyJsonElement(value))
        {
            identity.AddClaim(type, value, issuer);
        }

        return identity;
    }

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <param name="issuer">The issuer associated with the claim.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsPrincipal SetClaim(this ClaimsPrincipal principal, string type, JsonElement value, string issuer)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        principal.RemoveClaims(type);

        if (!IsEmptyJsonElement(value))
        {
            principal.AddClaim(type, value, issuer);
        }

        return principal;
    }

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetClaim(this ClaimsIdentity identity,
        string type, IDictionary<string, string?>? value)
        => identity.SetClaim(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsPrincipal SetClaim(this ClaimsPrincipal principal,
        string type, IDictionary<string, string?>? value)
        => principal.SetClaim(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <param name="issuer">The issuer associated with the claim.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetClaim(this ClaimsIdentity identity, string type,
        IDictionary<string, string?>? value, string issuer)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        identity.RemoveClaims(type);

        if (value is { Count: > 0 })
        {
            identity.AddClaim(type, value, issuer);
        }

        return identity;
    }

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claim.</param>
    /// <param name="value">The value associated with the claim.</param>
    /// <param name="issuer">The issuer associated with the claim.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsPrincipal SetClaim(this ClaimsPrincipal principal, string type,
        IDictionary<string, string?>? value, string issuer)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        principal.RemoveClaims(type);

        if (value is { Count: > 0 })
        {
            principal.AddClaim(type, value, issuer);
        }

        return principal;
    }

    /// <summary>
    /// Sets the claim values corresponding to the given type.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claims.</param>
    /// <param name="values">The values associated with the claims.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetClaims(this ClaimsIdentity identity, string type, ImmutableArray<string> values)
        => identity.SetClaims(type, values, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Sets the claim values corresponding to the given type.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claims.</param>
    /// <param name="values">The values associated with the claims.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsPrincipal SetClaims(this ClaimsPrincipal principal, string type, ImmutableArray<string> values)
        => principal.SetClaims(type, values, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Sets the claim values corresponding to the given type.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claims.</param>
    /// <param name="values">The values associated with the claims.</param>
    /// <param name="issuer">The issuer associated with the claims.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetClaims(this ClaimsIdentity identity,
        string type, ImmutableArray<string> values, string issuer)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        identity.RemoveClaims(type);

        foreach (var value in values.Distinct(StringComparer.Ordinal))
        {
            identity.AddClaim(type, value, issuer);
        }

        return identity;
    }

    /// <summary>
    /// Sets the claim values corresponding to the given type.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claims.</param>
    /// <param name="values">The values associated with the claims.</param>
    /// <param name="issuer">The issuer associated with the claims.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsPrincipal SetClaims(this ClaimsPrincipal principal,
        string type, ImmutableArray<string> values, string issuer)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        principal.RemoveClaims(type);

        foreach (var value in values.Distinct(StringComparer.Ordinal))
        {
            principal.AddClaim(type, value, issuer);
        }

        return principal;
    }

    /// <summary>
    /// Sets the claim values corresponding to the given type.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claims.</param>
    /// <param name="value">The JSON array from which claim values are extracted.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetClaims(this ClaimsIdentity identity, string type, JsonElement value)
        => identity.SetClaims(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Sets the claim values corresponding to the given type.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claims.</param>
    /// <param name="value">The JSON array from which claim values are extracted.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsPrincipal SetClaims(this ClaimsPrincipal principal, string type, JsonElement value)
        => principal.SetClaims(type, value, ClaimsIdentity.DefaultIssuer);

    /// <summary>
    /// Sets the claim values corresponding to the given type.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <param name="type">The type associated with the claims.</param>
    /// <param name="value">The JSON array from which claim values are extracted.</param>
    /// <param name="issuer">The issuer associated with the claims.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetClaims(this ClaimsIdentity identity, string type, JsonElement value, string issuer)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        identity.RemoveClaims(type);

        if (!IsEmptyJsonElement(value))
        {
            identity.AddClaims(type, value, issuer);
        }

        return identity;
    }

    /// <summary>
    /// Sets the claim value corresponding to the given type.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <param name="type">The type associated with the claims.</param>
    /// <param name="value">The JSON array from which claim values are extracted.</param>
    /// <param name="issuer">The issuer associated with the claims.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsPrincipal SetClaims(this ClaimsPrincipal principal, string type, JsonElement value, string issuer)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0184), nameof(type));
        }

        principal.RemoveClaims(type);

        if (!IsEmptyJsonElement(value))
        {
            principal.AddClaims(type, value, issuer);
        }

        return principal;
    }

    /// <summary>
    /// Gets the creation date stored in the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <returns>The creation date or <see langword="null"/> if the claim cannot be found.</returns>
    public static DateTimeOffset? GetCreationDate(this ClaimsIdentity identity)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        var claim = identity.FindFirst(Claims.Private.CreationDate);
        if (claim is null)
        {
            return null;
        }

        if (!DateTimeOffset.TryParseExact(claim.Value, "r", CultureInfo.InvariantCulture, DateTimeStyles.None, out var value))
        {
            return null;
        }

        return value;
    }

    /// <summary>
    /// Gets the creation date stored in the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <returns>The creation date or <see langword="null"/> if the claim cannot be found.</returns>
    public static DateTimeOffset? GetCreationDate(this ClaimsPrincipal principal)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        var claim = principal.FindFirst(Claims.Private.CreationDate);
        if (claim is null)
        {
            return null;
        }

        if (!DateTimeOffset.TryParseExact(claim.Value, "r", CultureInfo.InvariantCulture, DateTimeStyles.None, out var value))
        {
            return null;
        }

        return value;
    }

    /// <summary>
    /// Gets the expiration date stored in the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <returns>The expiration date or <see langword="null"/> if the claim cannot be found.</returns>
    public static DateTimeOffset? GetExpirationDate(this ClaimsIdentity identity)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        var claim = identity.FindFirst(Claims.Private.ExpirationDate);
        if (claim is null)
        {
            return null;
        }

        if (!DateTimeOffset.TryParseExact(claim.Value, "r", CultureInfo.InvariantCulture, DateTimeStyles.None, out var value))
        {
            return null;
        }

        return value;
    }

    /// <summary>
    /// Gets the expiration date stored in the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <returns>The expiration date or <see langword="null"/> if the claim cannot be found.</returns>
    public static DateTimeOffset? GetExpirationDate(this ClaimsPrincipal principal)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        var claim = principal.FindFirst(Claims.Private.ExpirationDate);
        if (claim is null)
        {
            return null;
        }

        if (!DateTimeOffset.TryParseExact(claim.Value, "r", CultureInfo.InvariantCulture, DateTimeStyles.None, out var value))
        {
            return null;
        }

        return value;
    }

    /// <summary>
    /// Gets the audiences list stored in the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <returns>The audiences list or an empty set if the claims cannot be found.</returns>
    public static ImmutableArray<string> GetAudiences(this ClaimsIdentity identity)
        => identity.GetClaims(Claims.Private.Audience);

    /// <summary>
    /// Gets the audiences list stored in the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <returns>The audiences list or an empty set if the claims cannot be found.</returns>
    public static ImmutableArray<string> GetAudiences(this ClaimsPrincipal principal)
        => principal.GetClaims(Claims.Private.Audience);

    /// <summary>
    /// Gets the presenters list stored in the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <returns>The presenters list or an empty set if the claims cannot be found.</returns>
    public static ImmutableArray<string> GetPresenters(this ClaimsIdentity identity)
        => identity.GetClaims(Claims.Private.Presenter);

    /// <summary>
    /// Gets the presenters list stored in the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <returns>The presenters list or an empty set if the claims cannot be found.</returns>
    public static ImmutableArray<string> GetPresenters(this ClaimsPrincipal principal)
        => principal.GetClaims(Claims.Private.Presenter);

    /// <summary>
    /// Gets the resources list stored in the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <returns>The resources list or an empty set if the claims cannot be found.</returns>
    public static ImmutableArray<string> GetResources(this ClaimsIdentity identity)
        => identity.GetClaims(Claims.Private.Resource);

    /// <summary>
    /// Gets the resources list stored in the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <returns>The resources list or an empty set if the claims cannot be found.</returns>
    public static ImmutableArray<string> GetResources(this ClaimsPrincipal principal)
        => principal.GetClaims(Claims.Private.Resource);

    /// <summary>
    /// Gets the scopes list stored in the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <returns>The scopes list or an empty set if the claim cannot be found.</returns>
    public static ImmutableArray<string> GetScopes(this ClaimsIdentity identity)
        => identity.GetClaims(Claims.Private.Scope);

    /// <summary>
    /// Gets the scopes list stored in the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <returns>The scopes list or an empty set if the claim cannot be found.</returns>
    public static ImmutableArray<string> GetScopes(this ClaimsPrincipal principal)
        => principal.GetClaims(Claims.Private.Scope);

    /// <summary>
    /// Gets the access token lifetime associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <returns>The access token lifetime or <see langword="null"/> if the claim cannot be found.</returns>
    public static TimeSpan? GetAccessTokenLifetime(this ClaimsIdentity identity)
        => GetLifetime(identity, Claims.Private.AccessTokenLifetime);

    /// <summary>
    /// Gets the access token lifetime associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <returns>The access token lifetime or <see langword="null"/> if the claim cannot be found.</returns>
    public static TimeSpan? GetAccessTokenLifetime(this ClaimsPrincipal principal)
        => GetLifetime(principal, Claims.Private.AccessTokenLifetime);

    /// <summary>
    /// Gets the authorization code lifetime associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <returns>The authorization code lifetime or <see langword="null"/> if the claim cannot be found.</returns>
    public static TimeSpan? GetAuthorizationCodeLifetime(this ClaimsIdentity identity)
        => GetLifetime(identity, Claims.Private.AuthorizationCodeLifetime);

    /// <summary>
    /// Gets the authorization code lifetime associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <returns>The authorization code lifetime or <see langword="null"/> if the claim cannot be found.</returns>
    public static TimeSpan? GetAuthorizationCodeLifetime(this ClaimsPrincipal principal)
        => GetLifetime(principal, Claims.Private.AuthorizationCodeLifetime);

    /// <summary>
    /// Gets the device code lifetime associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <returns>The device code lifetime or <see langword="null"/> if the claim cannot be found.</returns>
    public static TimeSpan? GetDeviceCodeLifetime(this ClaimsIdentity identity)
        => GetLifetime(identity, Claims.Private.DeviceCodeLifetime);

    /// <summary>
    /// Gets the device code lifetime associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <returns>The device code lifetime or <see langword="null"/> if the claim cannot be found.</returns>
    public static TimeSpan? GetDeviceCodeLifetime(this ClaimsPrincipal principal)
        => GetLifetime(principal, Claims.Private.DeviceCodeLifetime);

    /// <summary>
    /// Gets the identity token lifetime associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <returns>The identity token lifetime or <see langword="null"/> if the claim cannot be found.</returns>
    public static TimeSpan? GetIdentityTokenLifetime(this ClaimsIdentity identity)
        => GetLifetime(identity, Claims.Private.IdentityTokenLifetime);

    /// <summary>
    /// Gets the identity token lifetime associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <returns>The identity token lifetime or <see langword="null"/> if the claim cannot be found.</returns>
    public static TimeSpan? GetIdentityTokenLifetime(this ClaimsPrincipal principal)
        => GetLifetime(principal, Claims.Private.IdentityTokenLifetime);

    /// <summary>
    /// Gets the request token lifetime associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <returns>The request token lifetime or <see langword="null"/> if the claim cannot be found.</returns>
    public static TimeSpan? GetRequestTokenLifetime(this ClaimsIdentity identity)
        => GetLifetime(identity, Claims.Private.RequestTokenLifetime);

    /// <summary>
    /// Gets the request token lifetime associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <returns>The request token lifetime or <see langword="null"/> if the claim cannot be found.</returns>
    public static TimeSpan? GetRequestTokenLifetime(this ClaimsPrincipal principal)
        => GetLifetime(principal, Claims.Private.RequestTokenLifetime);

    /// <summary>
    /// Gets the refresh token lifetime associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <returns>The refresh token lifetime or <see langword="null"/> if the claim cannot be found.</returns>
    public static TimeSpan? GetRefreshTokenLifetime(this ClaimsIdentity identity)
        => GetLifetime(identity, Claims.Private.RefreshTokenLifetime);

    /// <summary>
    /// Gets the refresh token lifetime associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <returns>The refresh token lifetime or <see langword="null"/> if the claim cannot be found.</returns>
    public static TimeSpan? GetRefreshTokenLifetime(this ClaimsPrincipal principal)
        => GetLifetime(principal, Claims.Private.RefreshTokenLifetime);

    /// <summary>
    /// Gets the state token lifetime associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <returns>The state token lifetime or <see langword="null"/> if the claim cannot be found.</returns>
    public static TimeSpan? GetStateTokenLifetime(this ClaimsIdentity identity)
        => GetLifetime(identity, Claims.Private.StateTokenLifetime);

    /// <summary>
    /// Gets the state token lifetime associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <returns>The state token lifetime or <see langword="null"/> if the claim cannot be found.</returns>
    public static TimeSpan? GetStateTokenLifetime(this ClaimsPrincipal principal)
        => GetLifetime(principal, Claims.Private.StateTokenLifetime);

    /// <summary>
    /// Gets the user code lifetime associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <returns>The user code lifetime or <see langword="null"/> if the claim cannot be found.</returns>
    public static TimeSpan? GetUserCodeLifetime(this ClaimsIdentity identity)
        => GetLifetime(identity, Claims.Private.UserCodeLifetime);

    /// <summary>
    /// Gets the user code lifetime associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <returns>The user code lifetime or <see langword="null"/> if the claim cannot be found.</returns>
    public static TimeSpan? GetUserCodeLifetime(this ClaimsPrincipal principal)
        => GetLifetime(principal, Claims.Private.UserCodeLifetime);

    /// <summary>
    /// Gets the internal authorization identifier associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <returns>The unique identifier or <see langword="null"/> if the claim cannot be found.</returns>
    public static string? GetAuthorizationId(this ClaimsIdentity identity)
        => identity.GetClaim(Claims.Private.AuthorizationId);

    /// <summary>
    /// Gets the internal authorization identifier associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <returns>The unique identifier or <see langword="null"/> if the claim cannot be found.</returns>
    public static string? GetAuthorizationId(this ClaimsPrincipal principal)
        => principal.GetClaim(Claims.Private.AuthorizationId);

    /// <summary>
    /// Gets the internal token identifier associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <returns>The unique identifier or <see langword="null"/> if the claim cannot be found.</returns>
    public static string? GetTokenId(this ClaimsIdentity identity)
        => identity.GetClaim(Claims.Private.TokenId);

    /// <summary>
    /// Gets the internal token identifier associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <returns>The unique identifier or <see langword="null"/> if the claim cannot be found.</returns>
    public static string? GetTokenId(this ClaimsPrincipal principal)
        => principal.GetClaim(Claims.Private.TokenId);

    /// <summary>
    /// Gets the token type associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <returns>The token type or <see langword="null"/> if the claim cannot be found.</returns>
    public static string? GetTokenType(this ClaimsIdentity identity)
        => identity.GetClaim(Claims.Private.TokenType);

    /// <summary>
    /// Gets the token type associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <returns>The token type or <see langword="null"/> if the claim cannot be found.</returns>
    public static string? GetTokenType(this ClaimsPrincipal principal)
        => principal.GetClaim(Claims.Private.TokenType);

    /// <summary>
    /// Determines whether the claims identity contains the given audience.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="audience">The audience.</param>
    /// <returns><see langword="true"/> if the identity contains the given audience.</returns>
    public static bool HasAudience(this ClaimsIdentity identity, string audience)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(audience))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0186), nameof(audience));
        }

        return identity.HasClaim(Claims.Private.Audience, audience);
    }

    /// <summary>
    /// Determines whether the claims principal contains the given audience.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="audience">The audience.</param>
    /// <returns><see langword="true"/> if the principal contains the given audience.</returns>
    public static bool HasAudience(this ClaimsPrincipal principal, string audience)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrEmpty(audience))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0186), nameof(audience));
        }

        return principal.HasClaim(Claims.Private.Audience, audience);
    }

    /// <summary>
    /// Determines whether the claims identity contains the given presenter.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="presenter">The presenter.</param>
    /// <returns><see langword="true"/> if the identity contains the given presenter.</returns>
    public static bool HasPresenter(this ClaimsIdentity identity, string presenter)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(presenter))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0187), nameof(presenter));
        }

        return identity.HasClaim(Claims.Private.Presenter, presenter);
    }

    /// <summary>
    /// Determines whether the claims principal contains the given presenter.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="presenter">The presenter.</param>
    /// <returns><see langword="true"/> if the principal contains the given presenter.</returns>
    public static bool HasPresenter(this ClaimsPrincipal principal, string presenter)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrEmpty(presenter))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0187), nameof(presenter));
        }

        return principal.HasClaim(Claims.Private.Presenter, presenter);
    }

    /// <summary>
    /// Determines whether the claims identity contains the given resource.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="resource">The resource.</param>
    /// <returns><see langword="true"/> if the identity contains the given resource.</returns>
    public static bool HasResource(this ClaimsIdentity identity, string resource)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(resource))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0062), nameof(resource));
        }

        return identity.HasClaim(Claims.Private.Resource, resource);
    }

    /// <summary>
    /// Determines whether the claims principal contains the given resource.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="resource">The resource.</param>
    /// <returns><see langword="true"/> if the principal contains the given resource.</returns>
    public static bool HasResource(this ClaimsPrincipal principal, string resource)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrEmpty(resource))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0062), nameof(resource));
        }

        return principal.HasClaim(Claims.Private.Resource, resource);
    }

    /// <summary>
    /// Determines whether the claims identity contains the given scope.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="scope">The scope.</param>
    /// <returns><see langword="true"/> if the identity contains the given scope.</returns>
    public static bool HasScope(this ClaimsIdentity identity, string scope)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(scope))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0180), nameof(scope));
        }

        return identity.HasClaim(Claims.Private.Scope, scope);
    }

    /// <summary>
    /// Determines whether the claims principal contains the given scope.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="scope">The scope.</param>
    /// <returns><see langword="true"/> if the principal contains the given scope.</returns>
    public static bool HasScope(this ClaimsPrincipal principal, string scope)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrEmpty(scope))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0180), nameof(scope));
        }

        return principal.HasClaim(Claims.Private.Scope, scope);
    }

    /// <summary>
    /// Determines whether the token type associated with the claims identity matches the specified type.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="type">The token type.</param>
    /// <returns><see langword="true"/> if the token type matches the specified type.</returns>
    public static bool HasTokenType(this ClaimsIdentity identity, string type)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0188), nameof(type));
        }

        return string.Equals(identity.GetTokenType(), type, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Determines whether the token type associated with the claims principal matches the specified type.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="type">The token type.</param>
    /// <returns><see langword="true"/> if the token type matches the specified type.</returns>
    public static bool HasTokenType(this ClaimsPrincipal principal, string type)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0188), nameof(type));
        }

        return string.Equals(principal.GetTokenType(), type, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Sets the creation date in the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="date">The creation date</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetCreationDate(this ClaimsIdentity identity, DateTimeOffset? date)
        => identity.SetClaim(Claims.Private.CreationDate, date?.ToString("r", CultureInfo.InvariantCulture));

    /// <summary>
    /// Sets the creation date in the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="date">The creation date</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetCreationDate(this ClaimsPrincipal principal, DateTimeOffset? date)
        => principal.SetClaim(Claims.Private.CreationDate, date?.ToString("r", CultureInfo.InvariantCulture));

    /// <summary>
    /// Sets the expiration date in the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="date">The expiration date</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetExpirationDate(this ClaimsIdentity identity, DateTimeOffset? date)
        => identity.SetClaim(Claims.Private.ExpirationDate, date?.ToString("r", CultureInfo.InvariantCulture));

    /// <summary>
    /// Sets the expiration date in the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="date">The expiration date</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetExpirationDate(this ClaimsPrincipal principal, DateTimeOffset? date)
        => principal.SetClaim(Claims.Private.ExpirationDate, date?.ToString("r", CultureInfo.InvariantCulture));

    /// <summary>
    /// Sets the audiences list in the claims identity.
    /// Note: this method automatically excludes duplicate audiences.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="audiences">The audiences to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetAudiences(this ClaimsIdentity identity, ImmutableArray<string> audiences)
        => identity.SetClaims(Claims.Private.Audience, audiences);

    /// <summary>
    /// Sets the audiences list in the claims principal.
    /// Note: this method automatically excludes duplicate audiences.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="audiences">The audiences to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetAudiences(this ClaimsPrincipal principal, ImmutableArray<string> audiences)
        => principal.SetClaims(Claims.Private.Audience, audiences);

    /// <summary>
    /// Sets the audiences list in the claims identity.
    /// Note: this method automatically excludes duplicate audiences.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="audiences">The audiences to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetAudiences(this ClaimsIdentity identity, IEnumerable<string>? audiences)
        => identity.SetAudiences(audiences?.ToImmutableArray() ?? ImmutableArray<string>.Empty);

    /// <summary>
    /// Sets the audiences list in the claims principal.
    /// Note: this method automatically excludes duplicate audiences.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="audiences">The audiences to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetAudiences(this ClaimsPrincipal principal, IEnumerable<string>? audiences)
        => principal.SetAudiences(audiences?.ToImmutableArray() ?? ImmutableArray<string>.Empty);

    /// <summary>
    /// Sets the audiences list in the claims identity.
    /// Note: this method automatically excludes duplicate audiences.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="audiences">The audiences to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetAudiences(this ClaimsIdentity identity, params string[]? audiences)
        => identity.SetAudiences(audiences?.ToImmutableArray() ?? ImmutableArray<string>.Empty);

    /// <summary>
    /// Sets the audiences list in the claims principal.
    /// Note: this method automatically excludes duplicate audiences.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="audiences">The audiences to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetAudiences(this ClaimsPrincipal principal, params string[]? audiences)
        => principal.SetAudiences(audiences?.ToImmutableArray() ?? ImmutableArray<string>.Empty);

    /// <summary>
    /// Sets the presenters list in the claims identity.
    /// Note: this method automatically excludes duplicate presenters.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="presenters">The presenters to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetPresenters(this ClaimsIdentity identity, ImmutableArray<string> presenters)
        => identity.SetClaims(Claims.Private.Presenter, presenters);

    /// <summary>
    /// Sets the presenters list in the claims principal.
    /// Note: this method automatically excludes duplicate presenters.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="presenters">The presenters to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetPresenters(this ClaimsPrincipal principal, ImmutableArray<string> presenters)
        => principal.SetClaims(Claims.Private.Presenter, presenters);

    /// <summary>
    /// Sets the presenters list in the claims identity.
    /// Note: this method automatically excludes duplicate presenters.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="presenters">The presenters to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetPresenters(this ClaimsIdentity identity, IEnumerable<string>? presenters)
        => identity.SetPresenters(presenters?.ToImmutableArray() ?? ImmutableArray<string>.Empty);

    /// <summary>
    /// Sets the presenters list in the claims principal.
    /// Note: this method automatically excludes duplicate presenters.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="presenters">The presenters to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetPresenters(this ClaimsPrincipal principal, IEnumerable<string>? presenters)
        => principal.SetPresenters(presenters?.ToImmutableArray() ?? ImmutableArray<string>.Empty);

    /// <summary>
    /// Sets the presenters list in the claims identity.
    /// Note: this method automatically excludes duplicate presenters.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="presenters">The presenters to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetPresenters(this ClaimsIdentity identity, params string[]? presenters)
        => identity.SetPresenters(presenters?.ToImmutableArray() ?? ImmutableArray<string>.Empty);

    /// <summary>
    /// Sets the presenters list in the claims principal.
    /// Note: this method automatically excludes duplicate presenters.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="presenters">The presenters to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetPresenters(this ClaimsPrincipal principal, params string[]? presenters)
        => principal.SetPresenters(presenters?.ToImmutableArray() ?? ImmutableArray<string>.Empty);

    /// <summary>
    /// Sets the resources list in the claims identity.
    /// Note: this method automatically excludes duplicate resources.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="resources">The resources to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetResources(this ClaimsIdentity identity, ImmutableArray<string> resources)
        => identity.SetClaims(Claims.Private.Resource, resources);

    /// <summary>
    /// Sets the resources list in the claims principal.
    /// Note: this method automatically excludes duplicate resources.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="resources">The resources to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetResources(this ClaimsPrincipal principal, ImmutableArray<string> resources)
        => principal.SetClaims(Claims.Private.Resource, resources);

    /// <summary>
    /// Sets the resources list in the claims identity.
    /// Note: this method automatically excludes duplicate resources.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="resources">The resources to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetResources(this ClaimsIdentity identity, IEnumerable<string>? resources)
        => identity.SetResources(resources?.ToImmutableArray() ?? ImmutableArray<string>.Empty);

    /// <summary>
    /// Sets the resources list in the claims principal.
    /// Note: this method automatically excludes duplicate resources.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="resources">The resources to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetResources(this ClaimsPrincipal principal, IEnumerable<string>? resources)
        => principal.SetResources(resources?.ToImmutableArray() ?? ImmutableArray<string>.Empty);

    /// <summary>
    /// Sets the resources list in the claims identity.
    /// Note: this method automatically excludes duplicate resources.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="resources">The resources to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetResources(this ClaimsIdentity identity, params string[]? resources)
        => identity.SetResources(resources?.ToImmutableArray() ?? ImmutableArray<string>.Empty);

    /// <summary>
    /// Sets the resources list in the claims principal.
    /// Note: this method automatically excludes duplicate resources.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="resources">The resources to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetResources(this ClaimsPrincipal principal, params string[]? resources)
        => principal.SetResources(resources?.ToImmutableArray() ?? ImmutableArray<string>.Empty);

    /// <summary>
    /// Sets the scopes list in the claims identity.
    /// Note: this method automatically excludes duplicate scopes.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="scopes">The scopes to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetScopes(this ClaimsIdentity identity, ImmutableArray<string> scopes)
        => identity.SetClaims(Claims.Private.Scope, scopes);

    /// <summary>
    /// Sets the scopes list in the claims principal.
    /// Note: this method automatically excludes duplicate scopes.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="scopes">The scopes to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetScopes(this ClaimsPrincipal principal, ImmutableArray<string> scopes)
        => principal.SetClaims(Claims.Private.Scope, scopes);

    /// <summary>
    /// Sets the scopes list in the claims identity.
    /// Note: this method automatically excludes duplicate scopes.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="scopes">The scopes to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetScopes(this ClaimsIdentity identity, IEnumerable<string>? scopes)
        => identity.SetScopes(scopes?.ToImmutableArray() ?? ImmutableArray<string>.Empty);

    /// <summary>
    /// Sets the scopes list in the claims principal.
    /// Note: this method automatically excludes duplicate scopes.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="scopes">The scopes to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetScopes(this ClaimsPrincipal principal, IEnumerable<string>? scopes)
        => principal.SetScopes(scopes?.ToImmutableArray() ?? ImmutableArray<string>.Empty);

    /// <summary>
    /// Sets the scopes list in the claims identity.
    /// Note: this method automatically excludes duplicate scopes.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="scopes">The scopes to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetScopes(this ClaimsIdentity identity, params string[]? scopes)
        => identity.SetScopes(scopes?.ToImmutableArray() ?? ImmutableArray<string>.Empty);

    /// <summary>
    /// Sets the scopes list in the claims principal.
    /// Note: this method automatically excludes duplicate scopes.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="scopes">The scopes to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetScopes(this ClaimsPrincipal principal, params string[]? scopes)
        => principal.SetScopes(scopes?.ToImmutableArray() ?? ImmutableArray<string>.Empty);

    /// <summary>
    /// Sets the access token lifetime associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="lifetime">The access token lifetime to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetAccessTokenLifetime(this ClaimsIdentity identity, TimeSpan? lifetime)
        => identity.SetClaim(Claims.Private.AccessTokenLifetime, (long?) lifetime?.TotalSeconds);

    /// <summary>
    /// Sets the access token lifetime associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="lifetime">The access token lifetime to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetAccessTokenLifetime(this ClaimsPrincipal principal, TimeSpan? lifetime)
        => principal.SetClaim(Claims.Private.AccessTokenLifetime, (long?) lifetime?.TotalSeconds);

    /// <summary>
    /// Sets the authorization code lifetime associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="lifetime">The authorization code lifetime to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetAuthorizationCodeLifetime(this ClaimsIdentity identity, TimeSpan? lifetime)
        => identity.SetClaim(Claims.Private.AuthorizationCodeLifetime, (long?) lifetime?.TotalSeconds);

    /// <summary>
    /// Sets the authorization code lifetime associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="lifetime">The authorization code lifetime to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetAuthorizationCodeLifetime(this ClaimsPrincipal principal, TimeSpan? lifetime)
        => principal.SetClaim(Claims.Private.AuthorizationCodeLifetime, (long?) lifetime?.TotalSeconds);

    /// <summary>
    /// Sets the device code lifetime associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="lifetime">The device code lifetime to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetDeviceCodeLifetime(this ClaimsIdentity identity, TimeSpan? lifetime)
        => identity.SetClaim(Claims.Private.DeviceCodeLifetime, (long?) lifetime?.TotalSeconds);

    /// <summary>
    /// Sets the device code lifetime associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="lifetime">The device code lifetime to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetDeviceCodeLifetime(this ClaimsPrincipal principal, TimeSpan? lifetime)
        => principal.SetClaim(Claims.Private.DeviceCodeLifetime, (long?) lifetime?.TotalSeconds);

    /// <summary>
    /// Sets the identity token lifetime associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="lifetime">The identity token lifetime to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetIdentityTokenLifetime(this ClaimsIdentity identity, TimeSpan? lifetime)
        => identity.SetClaim(Claims.Private.IdentityTokenLifetime, (long?) lifetime?.TotalSeconds);

    /// <summary>
    /// Sets the identity token lifetime associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="lifetime">The identity token lifetime to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetIdentityTokenLifetime(this ClaimsPrincipal principal, TimeSpan? lifetime)
        => principal.SetClaim(Claims.Private.IdentityTokenLifetime, (long?) lifetime?.TotalSeconds);

    /// <summary>
    /// Sets the refresh token lifetime associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="lifetime">The refresh token lifetime to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetRefreshTokenLifetime(this ClaimsIdentity identity, TimeSpan? lifetime)
        => identity.SetClaim(Claims.Private.RefreshTokenLifetime, (long?) lifetime?.TotalSeconds);

    /// <summary>
    /// Sets the refresh token lifetime associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="lifetime">The refresh token lifetime to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetRefreshTokenLifetime(this ClaimsPrincipal principal, TimeSpan? lifetime)
        => principal.SetClaim(Claims.Private.RefreshTokenLifetime, (long?) lifetime?.TotalSeconds);

    /// <summary>
    /// Sets the state token lifetime associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="lifetime">The state token lifetime to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetStateTokenLifetime(this ClaimsIdentity identity, TimeSpan? lifetime)
        => identity.SetClaim(Claims.Private.StateTokenLifetime, (long?) lifetime?.TotalSeconds);

    /// <summary>
    /// Sets the state token lifetime associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="lifetime">The state token lifetime to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetStateTokenLifetime(this ClaimsPrincipal principal, TimeSpan? lifetime)
        => principal.SetClaim(Claims.Private.StateTokenLifetime, (long?) lifetime?.TotalSeconds);

    /// <summary>
    /// Sets the user code lifetime associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="lifetime">The user code lifetime to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetUserCodeLifetime(this ClaimsIdentity identity, TimeSpan? lifetime)
        => identity.SetClaim(Claims.Private.UserCodeLifetime, (long?) lifetime?.TotalSeconds);

    /// <summary>
    /// Sets the user code lifetime associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="lifetime">The user code lifetime to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetUserCodeLifetime(this ClaimsPrincipal principal, TimeSpan? lifetime)
        => principal.SetClaim(Claims.Private.UserCodeLifetime, (long?) lifetime?.TotalSeconds);

    /// <summary>
    /// Sets the internal authorization identifier associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="identifier">The unique identifier to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetAuthorizationId(this ClaimsIdentity identity, string? identifier)
        => identity.SetClaim(Claims.Private.AuthorizationId, identifier);

    /// <summary>
    /// Sets the internal authorization identifier associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="identifier">The unique identifier to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetAuthorizationId(this ClaimsPrincipal principal, string? identifier)
        => principal.SetClaim(Claims.Private.AuthorizationId, identifier);

    /// <summary>
    /// Sets the internal token identifier associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="identifier">The unique identifier to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetTokenId(this ClaimsIdentity identity, string? identifier)
        => identity.SetClaim(Claims.Private.TokenId, identifier);

    /// <summary>
    /// Sets the internal token identifier associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="identifier">The unique identifier to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetTokenId(this ClaimsPrincipal principal, string? identifier)
        => principal.SetClaim(Claims.Private.TokenId, identifier);

    /// <summary>
    /// Sets the token type associated with the claims identity.
    /// </summary>
    /// <param name="identity">The claims identity.</param>
    /// <param name="type">The token type to store.</param>
    /// <returns>The claims identity.</returns>
    public static ClaimsIdentity SetTokenType(this ClaimsIdentity identity, string? type)
        => identity.SetClaim(Claims.Private.TokenType, type);

    /// <summary>
    /// Sets the token type associated with the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <param name="type">The token type to store.</param>
    /// <returns>The claims principal.</returns>
    public static ClaimsPrincipal SetTokenType(this ClaimsPrincipal principal, string? type)
        => principal.SetClaim(Claims.Private.TokenType, type);

    private static ImmutableArray<string> GetValues(string? source, char[] separators)
    {
        Debug.Assert(separators is { Length: > 0 }, SR.GetResourceString(SR.ID4001));

        if (string.IsNullOrEmpty(source))
        {
            return ImmutableArray<string>.Empty;
        }

        var builder = ImmutableArray.CreateBuilder<string>();

        foreach (var element in new StringTokenizer(source, separators))
        {
            var segment = Trim(element, separators);
            if (!segment.HasValue || segment.Length is 0)
            {
                continue;
            }

            if (builder.Contains(segment.Value, StringComparer.Ordinal))
            {
                continue;
            }

            builder.Add(segment.Value);
        }

        return builder.ToImmutable();
    }

    private static bool HasValue(string? source, string value, char[] separators)
    {
        Debug.Assert(!string.IsNullOrEmpty(value), SR.GetResourceString(SR.ID4002));
        Debug.Assert(separators is { Length: > 0 }, SR.GetResourceString(SR.ID4001));

        if (string.IsNullOrEmpty(source))
        {
            return false;
        }

        foreach (var element in new StringTokenizer(source, separators))
        {
            var segment = Trim(element, separators);
            if (!segment.HasValue || segment.Length is 0)
            {
                continue;
            }

            if (segment.Equals(value, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static StringSegment TrimStart(StringSegment segment, char[] separators)
    {
        Debug.Assert(separators is { Length: > 0 }, SR.GetResourceString(SR.ID4001));

        if (!segment.HasValue || segment.Length is 0)
        {
            return segment;
        }

        var index = segment.Offset;

        while (index < segment.Offset + segment.Length)
        {
            if (!IsSeparator(segment.Buffer[index], separators))
            {
                break;
            }

            index++;
        }

        return new StringSegment(segment.Buffer, index, segment.Offset + segment.Length - index);
    }

    private static StringSegment TrimEnd(StringSegment segment, char[] separators)
    {
        Debug.Assert(separators is { Length: > 0 }, SR.GetResourceString(SR.ID4001));

        if (!segment.HasValue || segment.Length is 0)
        {
            return segment;
        }

        var index = segment.Offset + segment.Length - 1;

        while (index >= segment.Offset)
        {
            if (!IsSeparator(segment.Buffer[index], separators))
            {
                break;
            }

            index--;
        }

        return new StringSegment(segment.Buffer, segment.Offset, index - segment.Offset + 1);
    }

    private static StringSegment Trim(StringSegment segment, char[] separators)
    {
        Debug.Assert(separators is { Length: > 0 }, SR.GetResourceString(SR.ID4001));

        return TrimEnd(TrimStart(segment, separators), separators);
    }

    private static bool IsSeparator(char character, char[] separators)
    {
        Debug.Assert(separators is { Length: > 0 }, SR.GetResourceString(SR.ID4001));

        for (var index = 0; index < separators!.Length; index++)
        {
            if (character == separators[index])
            {
                return true;
            }
        }

        return false;
    }

    private static string GetClaimValueType(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.String                      => ClaimValueTypes.String,
        JsonValueKind.True or JsonValueKind.False => ClaimValueTypes.Boolean,

        JsonValueKind.Number when element.TryGetInt32(out _)  => ClaimValueTypes.Integer32,
        JsonValueKind.Number when element.TryGetInt64(out _)  => ClaimValueTypes.Integer64,
        JsonValueKind.Number when element.TryGetUInt32(out _) => ClaimValueTypes.UInteger32,
        JsonValueKind.Number when element.TryGetUInt64(out _) => ClaimValueTypes.UInteger64,
        JsonValueKind.Number when element.TryGetDouble(out _) => ClaimValueTypes.Double,

        JsonValueKind.Null or JsonValueKind.Undefined => "JSON_NULL",
        JsonValueKind.Array                           => "JSON_ARRAY",
        JsonValueKind.Object or _                     => "JSON"
    };

    private static TimeSpan? GetLifetime(ClaimsIdentity identity, string type)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(nameof(identity));
        }

        var value = identity.GetClaim(type);
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        if (double.TryParse(value, NumberStyles.Number, CultureInfo.InvariantCulture, out double result))
        {
            return TimeSpan.FromSeconds(result);
        }

        return null;
    }

    private static TimeSpan? GetLifetime(ClaimsPrincipal principal, string type)
    {
        if (principal is null)
        {
            throw new ArgumentNullException(nameof(principal));
        }

        var value = principal.GetClaim(type);
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        if (double.TryParse(value, NumberStyles.Number, CultureInfo.InvariantCulture, out double result))
        {
            return TimeSpan.FromSeconds(result);
        }

        return null;
    }

    private static bool IsEmptyJsonElement(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Undefined or JsonValueKind.Null:
                return true;

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

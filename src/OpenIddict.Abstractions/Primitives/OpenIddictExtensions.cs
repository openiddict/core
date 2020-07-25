﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using JetBrains.Annotations;
using Microsoft.Extensions.Primitives;
using static OpenIddict.Abstractions.OpenIddictConstants;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Abstractions
{
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
        public static ImmutableArray<string> GetAcrValues([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.AcrValues))
            {
                return ImmutableArray.Create<string>();
            }

            return GetValues(request.AcrValues, Separators.Space).Distinct(StringComparer.Ordinal).ToImmutableArray();
        }

        /// <summary>
        /// Extracts the prompt values from an <see cref="OpenIddictRequest"/>.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        public static ImmutableArray<string> GetPrompts([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.Prompt))
            {
                return ImmutableArray.Create<string>();
            }

            return GetValues(request.Prompt, Separators.Space).Distinct(StringComparer.Ordinal).ToImmutableArray();
        }

        /// <summary>
        /// Extracts the response types from an <see cref="OpenIddictRequest"/>.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        public static ImmutableArray<string> GetResponseTypes([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.ResponseType))
            {
                return ImmutableArray.Create<string>();
            }

            return GetValues(request.ResponseType, Separators.Space).Distinct(StringComparer.Ordinal).ToImmutableArray();
        }

        /// <summary>
        /// Extracts the scopes from an <see cref="OpenIddictRequest"/>.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        public static ImmutableArray<string> GetScopes([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.Scope))
            {
                return ImmutableArray.Create<string>();
            }

            return GetValues(request.Scope, Separators.Space).Distinct(StringComparer.Ordinal).ToImmutableArray();
        }

        /// <summary>
        /// Determines whether the requested authentication context class values contain the specified item.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <param name="value">The component to look for in the parameter.</param>
        public static bool HasAcrValue([NotNull] this OpenIddictRequest request, [NotNull] string value)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1176), nameof(value));
            }

            return HasValue(request.AcrValues, value, Separators.Space);
        }

        /// <summary>
        /// Determines whether the requested prompt contains the specified value.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <param name="prompt">The component to look for in the parameter.</param>
        public static bool HasPrompt([NotNull] this OpenIddictRequest request, [NotNull] string prompt)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(prompt))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1177), nameof(prompt));
            }

            return HasValue(request.Prompt, prompt, Separators.Space);
        }

        /// <summary>
        /// Determines whether the requested response type contains the specified value.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <param name="type">The component to look for in the parameter.</param>
        public static bool HasResponseType([NotNull] this OpenIddictRequest request, [NotNull] string type)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1178), nameof(type));
            }

            return HasValue(request.ResponseType, type, Separators.Space);
        }

        /// <summary>
        /// Determines whether the requested scope contains the specified value.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <param name="scope">The component to look for in the parameter.</param>
        public static bool HasScope([NotNull] this OpenIddictRequest request, [NotNull] string scope)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(scope))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1179), nameof(scope));
            }

            return HasValue(request.Scope, scope, Separators.Space);
        }

        /// <summary>
        /// Determines whether the "response_type" parameter corresponds to the "none" response type.
        /// See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a response_type=none request, <c>false</c> otherwise.</returns>
        public static bool IsNoneFlow([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.ResponseType))
            {
                return false;
            }

            var segment = Trim(new StringSegment(request.ResponseType), Separators.Space);
            if (segment.Length == 0)
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
        /// <returns><c>true</c> if the request is a code flow request, <c>false</c> otherwise.</returns>
        public static bool IsAuthorizationCodeFlow([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.ResponseType))
            {
                return false;
            }

            var segment = Trim(new StringSegment(request.ResponseType), Separators.Space);
            if (segment.Length == 0)
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
        /// <returns><c>true</c> if the request is an implicit flow request, <c>false</c> otherwise.</returns>
        public static bool IsImplicitFlow([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
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
                if (segment.Length == 0)
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
        /// <returns><c>true</c> if the request is an hybrid flow request, <c>false</c> otherwise.</returns>
        public static bool IsHybridFlow([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
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
                if (segment.Length == 0)
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
        /// <c>true</c> if the request specified the fragment response mode or if
        /// it's the default value for the requested flow, <c>false</c> otherwise.
        /// </returns>
        public static bool IsFragmentResponseMode([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
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
        /// <c>true</c> if the request specified the query response mode or if
        /// it's the default value for the requested flow, <c>false</c> otherwise.
        /// </returns>
        public static bool IsQueryResponseMode([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
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
        /// <c>true</c> if the request specified the form post response mode or if
        /// it's the default value for the requested flow, <c>false</c> otherwise.
        /// </returns>
        public static bool IsFormPostResponseMode([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
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
        /// <returns><c>true</c> if the request is a code grant request, <c>false</c> otherwise.</returns>
        public static bool IsAuthorizationCodeGrantType([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
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
        /// <returns><c>true</c> if the request is a client credentials grant request, <c>false</c> otherwise.</returns>
        public static bool IsClientCredentialsGrantType([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
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
        /// <returns><c>true</c> if the request is a device code grant request, <c>false</c> otherwise.</returns>
        public static bool IsDeviceCodeGrantType([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
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
        /// <returns><c>true</c> if the request is a password grant request, <c>false</c> otherwise.</returns>
        public static bool IsPasswordGrantType([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
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
        /// <returns><c>true</c> if the request is a refresh token grant request, <c>false</c> otherwise.</returns>
        public static bool IsRefreshTokenGrantType([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
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
        public static ImmutableArray<string> GetDestinations([NotNull] this Claim claim)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            claim.Properties.TryGetValue(Properties.Destinations, out string destinations);

            if (string.IsNullOrEmpty(destinations))
            {
                return ImmutableArray.Create<string>();
            }

            return JsonSerializer.Deserialize<IEnumerable<string>>(destinations)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToImmutableArray();
        }

        /// <summary>
        /// Determines whether the given claim contains the required destination.
        /// </summary>
        /// <param name="claim">The <see cref="Claim"/> instance.</param>
        /// <param name="destination">The required destination.</param>
        public static bool HasDestination([NotNull] this Claim claim, [NotNull] string destination)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            if (string.IsNullOrEmpty(destination))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1180), nameof(destination));
            }

            claim.Properties.TryGetValue(Properties.Destinations, out string destinations);

            if (string.IsNullOrEmpty(destinations))
            {
                return false;
            }

            return JsonSerializer.Deserialize<IEnumerable<string>>(destinations)
                .Contains(destination, StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Adds specific destinations to a claim.
        /// </summary>
        /// <param name="claim">The <see cref="Claim"/> instance.</param>
        /// <param name="destinations">The destinations.</param>
        public static Claim SetDestinations([NotNull] this Claim claim, ImmutableArray<string> destinations)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            if (destinations.IsDefaultOrEmpty)
            {
                claim.Properties.Remove(Properties.Destinations);

                return claim;
            }

            if (destinations.Any(destination => string.IsNullOrEmpty(destination)))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1181), nameof(destinations));
            }

            claim.Properties[Properties.Destinations] =
                JsonSerializer.Serialize(destinations.Distinct(StringComparer.OrdinalIgnoreCase), new JsonSerializerOptions
                {
                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                    WriteIndented = false
                });

            return claim;
        }

        /// <summary>
        /// Adds specific destinations to a claim.
        /// </summary>
        /// <param name="claim">The <see cref="Claim"/> instance.</param>
        /// <param name="destinations">The destinations.</param>
        public static Claim SetDestinations([NotNull] this Claim claim, [CanBeNull] IEnumerable<string> destinations)
            => claim.SetDestinations(destinations?.ToImmutableArray() ?? ImmutableArray.Create<string>());

        /// <summary>
        /// Adds specific destinations to a claim.
        /// </summary>
        /// <param name="claim">The <see cref="Claim"/> instance.</param>
        /// <param name="destinations">The destinations.</param>
        public static Claim SetDestinations([NotNull] this Claim claim, [CanBeNull] params string[] destinations)
            => claim.SetDestinations(destinations?.ToImmutableArray() ?? ImmutableArray.Create<string>());

        /// <summary>
        /// Gets the destinations associated with all the claims of the given principal.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <returns>The destinations, returned as a flattened dictionary.</returns>
        public static ImmutableDictionary<string, string[]> GetDestinations([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            var builder = ImmutableDictionary.CreateBuilder<string, string[]>(StringComparer.Ordinal);

            foreach (var group in principal.Claims.GroupBy(claim => claim.Type))
            {
                var claims = group.ToList();

                var destinations = new HashSet<string>(claims[0].GetDestinations(), StringComparer.OrdinalIgnoreCase);
                if (destinations.Count != 0)
                {
                    // Ensure the other claims of the same type use the same exact destinations.
                    for (var index = 0; index < claims.Count; index++)
                    {
                        if (!destinations.SetEquals(claims[index].GetDestinations()))
                        {
                            throw new InvalidOperationException(SR.FormatID1182(group.Key));
                        }
                    }

                    builder.Add(group.Key, destinations.ToArray());
                }
            }

            return builder.ToImmutable();
        }

        /// <summary>
        /// Sets the destinations associated with all the claims of the given principal.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="destinations">The destinations, as a flattened dictionary.</param>
        /// <returns>The principal.</returns>
        public static ClaimsPrincipal SetDestinations(
            [NotNull] this ClaimsPrincipal principal,
            [NotNull] ImmutableDictionary<string, string[]> destinations)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (destinations == null)
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
        /// Clones an identity by filtering its claims and the claims of its actor, recursively.
        /// </summary>
        /// <param name="identity">The <see cref="ClaimsIdentity"/> instance to filter.</param>
        /// <param name="filter">
        /// The delegate filtering the claims: return <c>true</c>
        /// to accept the claim, <c>false</c> to remove it.
        /// </param>
        public static ClaimsIdentity Clone(
            [NotNull] this ClaimsIdentity identity,
            [NotNull] Func<Claim, bool> filter)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (filter == null)
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

            if (clone.Actor != null)
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
        /// The delegate filtering the claims: return <c>true</c>
        /// to accept the claim, <c>false</c> to remove it.
        /// </param>
        public static ClaimsPrincipal Clone(
            [NotNull] this ClaimsPrincipal principal,
            [NotNull] Func<Claim, bool> filter)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (filter == null)
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
        public static ClaimsIdentity AddClaim(
            [NotNull] this ClaimsIdentity identity,
            [NotNull] string type, [NotNull] string value)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1183), nameof(type));
            }

            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1184), nameof(value));
            }

            identity.AddClaim(new Claim(type, value));
            return identity;
        }

        /// <summary>
        /// Adds a claim to a given identity and specify one or more destinations.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <param name="type">The type associated with the claim.</param>
        /// <param name="value">The value associated with the claim.</param>
        /// <param name="destinations">The destinations associated with the claim.</param>
        public static ClaimsIdentity AddClaim(
            [NotNull] this ClaimsIdentity identity,
            [NotNull] string type, [NotNull] string value,
            [NotNull] ImmutableArray<string> destinations)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1183), nameof(type));
            }

            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1184), nameof(value));
            }

            if (destinations == null)
            {
                throw new ArgumentNullException(nameof(destinations));
            }

            identity.AddClaim(new Claim(type, value).SetDestinations(destinations));
            return identity;
        }

        /// <summary>
        /// Adds a claim to a given identity and specify one or more destinations.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <param name="type">The type associated with the claim.</param>
        /// <param name="value">The value associated with the claim.</param>
        /// <param name="destinations">The destinations associated with the claim.</param>
        public static ClaimsIdentity AddClaim(
            [NotNull] this ClaimsIdentity identity,
            [NotNull] string type, [NotNull] string value,
            [NotNull] params string[] destinations)
            => identity.AddClaim(type, value, destinations?.ToImmutableArray() ?? ImmutableArray.Create<string>());

        /// <summary>
        /// Gets the claim value corresponding to the given type.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <param name="type">The type associated with the claim.</param>
        /// <returns>The claim value.</returns>
        public static string GetClaim([NotNull] this ClaimsIdentity identity, [NotNull] string type)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1183), nameof(type));
            }

            return identity.FindFirst(type)?.Value;
        }

        /// <summary>
        /// Gets the claim value corresponding to the given type.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="type">The type associated with the claim.</param>
        /// <returns>The claim value.</returns>
        public static string GetClaim([NotNull] this ClaimsPrincipal principal, [NotNull] string type)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1183), nameof(type));
            }

            return principal.FindFirst(type)?.Value;
        }

        /// <summary>
        /// Gets the claim values corresponding to the given type.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <param name="type">The type associated with the claims.</param>
        /// <returns>The claim values.</returns>
        public static ImmutableArray<string> GetClaims([NotNull] this ClaimsIdentity identity, [NotNull] string type)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1183), nameof(type));
            }

            return identity.FindAll(type).Select(claim => claim.Value).Distinct(StringComparer.Ordinal).ToImmutableArray();
        }

        /// <summary>
        /// Determines whether the claims identity contains at least one claim of the specified type.
        /// </summary>
        /// <param name="identity">The claims identity.</param>
        /// <param name="type">The claim type.</param>
        /// <returns><c>true</c> if the identity contains at least one claim of the specified type.</returns>
        public static bool HasClaim([NotNull] this ClaimsIdentity identity, [NotNull] string type)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1183), nameof(type));
            }

            return identity.FindAll(type).Any();
        }

        /// <summary>
        /// Gets the claim values corresponding to the given type.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="type">The type associated with the claims.</param>
        /// <returns>The claim values.</returns>
        public static ImmutableArray<string> GetClaims([NotNull] this ClaimsPrincipal principal, [NotNull] string type)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1183), nameof(type));
            }

            return principal.FindAll(type).Select(claim => claim.Value).Distinct(StringComparer.Ordinal).ToImmutableArray();
        }

        /// <summary>
        /// Determines whether the claims principal contains at least one claim of the specified type.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="type">The claim type.</param>
        /// <returns><c>true</c> if the principal contains at least one claim of the specified type.</returns>
        public static bool HasClaim([NotNull] this ClaimsPrincipal principal, [NotNull] string type)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1183), nameof(type));
            }

            return principal.FindAll(type).Any();
        }

        /// <summary>
        /// Removes all the claims corresponding to the given type.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <param name="type">The type associated with the claims.</param>
        /// <returns>The claims identity.</returns>
        public static ClaimsIdentity RemoveClaims([NotNull] this ClaimsIdentity identity, [NotNull] string type)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1183), nameof(type));
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
        public static ClaimsPrincipal RemoveClaims([NotNull] this ClaimsPrincipal principal, [NotNull] string type)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1183), nameof(type));
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
        /// <param name="type">The type associated with the claims.</param>
        /// <param name="value">The claim value.</param>
        /// <returns>The claims identity.</returns>
        public static ClaimsIdentity SetClaims(
            [NotNull] this ClaimsIdentity identity,
            [NotNull] string type, [CanBeNull] string value)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1183), nameof(type));
            }

            identity.RemoveClaims(type);

            if (!string.IsNullOrEmpty(value))
            {
                identity.AddClaim(type, value);
            }

            return identity;
        }

        /// <summary>
        /// Sets the claim value corresponding to the given type.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="type">The type associated with the claims.</param>
        /// <param name="value">The claim value.</param>
        /// <returns>The claims identity.</returns>
        public static ClaimsPrincipal SetClaim(
            [NotNull] this ClaimsPrincipal principal,
            [NotNull] string type, [CanBeNull] string value)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1183), nameof(type));
            }

            principal.RemoveClaims(type);

            if (!string.IsNullOrEmpty(value))
            {
                ((ClaimsIdentity) principal.Identity).AddClaim(type, value);
            }

            return principal;
        }

        /// <summary>
        /// Sets the claim values corresponding to the given type.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <param name="type">The type associated with the claims.</param>
        /// <param name="values">The claim values.</param>
        /// <returns>The claims identity.</returns>
        public static ClaimsIdentity SetClaims([NotNull] this ClaimsIdentity identity,
            [NotNull] string type, [NotNull] ImmutableArray<string> values)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1183), nameof(type));
            }

            identity.RemoveClaims(type);

            foreach (var value in values.Distinct(StringComparer.Ordinal))
            {
                identity.AddClaim(type, value);
            }

            return identity;
        }

        /// <summary>
        /// Sets the claim values corresponding to the given type.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="type">The type associated with the claims.</param>
        /// <param name="values">The claim values.</param>
        /// <returns>The claims identity.</returns>
        public static ClaimsPrincipal SetClaims([NotNull] this ClaimsPrincipal principal,
            [NotNull] string type, [NotNull] ImmutableArray<string> values)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1183), nameof(type));
            }

            principal.RemoveClaims(type);

            foreach (var value in values.Distinct(StringComparer.Ordinal))
            {
                ((ClaimsIdentity) principal.Identity).AddClaim(type, value);
            }

            return principal;
        }

        /// <summary>
        /// Gets the creation date stored in the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The creation date or <c>null</c> if the claim cannot be found.</returns>
        public static DateTimeOffset? GetCreationDate([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            var claim = principal.FindFirst(Claims.Private.CreationDate);
            if (claim == null)
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
        /// <returns>The expiration date or <c>null</c> if the claim cannot be found.</returns>
        public static DateTimeOffset? GetExpirationDate([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            var claim = principal.FindFirst(Claims.Private.ExpirationDate);
            if (claim == null)
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
        /// Gets the audiences list stored in the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The audiences list or an empty set if the claims cannot be found.</returns>
        public static ImmutableArray<string> GetAudiences([NotNull] this ClaimsPrincipal principal)
            => principal.GetClaims(Claims.Private.Audience);

        /// <summary>
        /// Gets the presenters list stored in the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The presenters list or an empty set if the claims cannot be found.</returns>
        public static ImmutableArray<string> GetPresenters([NotNull] this ClaimsPrincipal principal)
            => principal.GetClaims(Claims.Private.Presenter);

        /// <summary>
        /// Gets the resources list stored in the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The resources list or an empty set if the claims cannot be found.</returns>
        public static ImmutableArray<string> GetResources([NotNull] this ClaimsPrincipal principal)
            => principal.GetClaims(Claims.Private.Resource);

        /// <summary>
        /// Gets the scopes list stored in the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The scopes list or an empty set if the claim cannot be found.</returns>
        public static ImmutableArray<string> GetScopes([NotNull] this ClaimsPrincipal principal)
            => principal.GetClaims(Claims.Private.Scope);

        /// <summary>
        /// Gets the access token lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The access token lifetime or <c>null</c> if the claim cannot be found.</returns>
        public static TimeSpan? GetAccessTokenLifetime([NotNull] this ClaimsPrincipal principal)
            => GetLifetime(principal, Claims.Private.AccessTokenLifetime);

        /// <summary>
        /// Gets the authorization code lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The authorization code lifetime or <c>null</c> if the claim cannot be found.</returns>
        public static TimeSpan? GetAuthorizationCodeLifetime([NotNull] this ClaimsPrincipal principal)
            => GetLifetime(principal, Claims.Private.AuthorizationCodeLifetime);

        /// <summary>
        /// Gets the device code lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The device code lifetime or <c>null</c> if the claim cannot be found.</returns>
        public static TimeSpan? GetDeviceCodeLifetime([NotNull] this ClaimsPrincipal principal)
            => GetLifetime(principal, Claims.Private.DeviceCodeLifetime);

        /// <summary>
        /// Gets the identity token lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The identity token lifetime or <c>null</c> if the claim cannot be found.</returns>
        public static TimeSpan? GetIdentityTokenLifetime([NotNull] this ClaimsPrincipal principal)
            => GetLifetime(principal, Claims.Private.IdentityTokenLifetime);

        /// <summary>
        /// Gets the refresh token lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The refresh token lifetime or <c>null</c> if the claim cannot be found.</returns>
        public static TimeSpan? GetRefreshTokenLifetime([NotNull] this ClaimsPrincipal principal)
            => GetLifetime(principal, Claims.Private.RefreshTokenLifetime);

        /// <summary>
        /// Gets the user code lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The user code lifetime or <c>null</c> if the claim cannot be found.</returns>
        public static TimeSpan? GetUserCodeLifetime([NotNull] this ClaimsPrincipal principal)
            => GetLifetime(principal, Claims.Private.UserCodeLifetime);

        /// <summary>
        /// Gets the internal authorization identifier associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The unique identifier or <c>null</c> if the claim cannot be found.</returns>
        public static string GetAuthorizationId([NotNull] this ClaimsPrincipal principal)
            => principal.GetClaim(Claims.Private.AuthorizationId);

        /// <summary>
        /// Gets the internal token identifier associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The unique identifier or <c>null</c> if the claim cannot be found.</returns>
        public static string GetTokenId([NotNull] this ClaimsPrincipal principal)
            => principal.GetClaim(Claims.Private.TokenId);

        /// <summary>
        /// Gets the token type associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The token type or <c>null</c> if the claim cannot be found.</returns>
        public static string GetTokenType([NotNull] this ClaimsPrincipal principal)
            => principal.GetClaim(Claims.Private.TokenType);

        /// <summary>
        /// Determines whether the claims principal contains at least one audience.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns><c>true</c> if the principal contains at least one audience.</returns>
        public static bool HasAudience([NotNull] this ClaimsPrincipal principal)
            => principal.HasClaim(Claims.Private.Audience);

        /// <summary>
        /// Determines whether the claims principal contains the given audience.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="audience">The audience.</param>
        /// <returns><c>true</c> if the principal contains the given audience.</returns>
        public static bool HasAudience([NotNull] this ClaimsPrincipal principal, [NotNull] string audience)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (string.IsNullOrEmpty(audience))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1185), nameof(audience));
            }

            return principal.HasClaim(Claims.Private.Audience, audience);
        }

        /// <summary>
        /// Determines whether the claims principal contains at least one presenter.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns><c>true</c> if the principal contains at least one presenter.</returns>
        public static bool HasPresenter([NotNull] this ClaimsPrincipal principal)
            => principal.HasClaim(Claims.Private.Presenter);

        /// <summary>
        /// Determines whether the claims principal contains the given presenter.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="presenter">The presenter.</param>
        /// <returns><c>true</c> if the principal contains the given presenter.</returns>
        public static bool HasPresenter([NotNull] this ClaimsPrincipal principal, [NotNull] string presenter)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (string.IsNullOrEmpty(presenter))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1186), nameof(presenter));
            }

            return principal.HasClaim(Claims.Private.Presenter, presenter);
        }

        /// <summary>
        /// Determines whether the claims principal contains at least one resource.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns><c>true</c> if the principal contains at least one resource.</returns>
        public static bool HasResource([NotNull] this ClaimsPrincipal principal)
            => principal.HasClaim(Claims.Private.Resource);

        /// <summary>
        /// Determines whether the claims principal contains the given resource.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="resource">The resource.</param>
        /// <returns><c>true</c> if the principal contains the given resource.</returns>
        public static bool HasResource([NotNull] this ClaimsPrincipal principal, [NotNull] string resource)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (string.IsNullOrEmpty(resource))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1061), nameof(resource));
            }

            return principal.HasClaim(Claims.Private.Resource, resource);
        }

        /// <summary>
        /// Determines whether the claims principal contains at least one scope.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns><c>true</c> if the principal contains at least one scope.</returns>
        public static bool HasScope([NotNull] this ClaimsPrincipal principal)
            => principal.HasClaim(Claims.Private.Scope);

        /// <summary>
        /// Determines whether the claims principal contains the given scope.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="scope">The scope.</param>
        /// <returns><c>true</c> if the principal contains the given scope.</returns>
        public static bool HasScope([NotNull] this ClaimsPrincipal principal, [NotNull] string scope)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (string.IsNullOrEmpty(scope))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1179), nameof(scope));
            }

            return principal.HasClaim(Claims.Private.Scope, scope);
        }

        /// <summary>
        /// Determines whether the token type associated with the claims principal matches the specified type.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="type">The token type.</param>
        /// <returns><c>true</c> if the token type matches the specified type.</returns>
        public static bool HasTokenType([NotNull] this ClaimsPrincipal principal, [NotNull] string type)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1187), nameof(type));
            }

            return string.Equals(principal.GetTokenType(), type, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Sets the creation date in the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="date">The creation date</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetCreationDate([NotNull] this ClaimsPrincipal principal, [CanBeNull] DateTimeOffset? date)
            => principal.SetClaim(Claims.Private.CreationDate, date?.ToString("r", CultureInfo.InvariantCulture));

        /// <summary>
        /// Sets the expiration date in the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="date">The expiration date</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetExpirationDate([NotNull] this ClaimsPrincipal principal, [CanBeNull] DateTimeOffset? date)
            => principal.SetClaim(Claims.Private.ExpirationDate, date?.ToString("r", CultureInfo.InvariantCulture));

        /// <summary>
        /// Sets the audiences list in the claims principal.
        /// Note: this method automatically excludes duplicate audiences.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="audiences">The audiences to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetAudiences(
            [NotNull] this ClaimsPrincipal principal, [CanBeNull] ImmutableArray<string> audiences)
            => principal.SetClaims(Claims.Private.Audience, audiences);

        /// <summary>
        /// Sets the audiences list in the claims principal.
        /// Note: this method automatically excludes duplicate audiences.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="audiences">The audiences to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetAudiences(
            [NotNull] this ClaimsPrincipal principal, [CanBeNull] IEnumerable<string> audiences)
            => principal.SetAudiences(audiences?.ToImmutableArray() ?? ImmutableArray.Create<string>());

        /// <summary>
        /// Sets the audiences list in the claims principal.
        /// Note: this method automatically excludes duplicate audiences.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="audiences">The audiences to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetAudiences(
            [NotNull] this ClaimsPrincipal principal, [CanBeNull] params string[] audiences)
            => principal.SetAudiences(audiences?.ToImmutableArray() ?? ImmutableArray.Create<string>());

        /// <summary>
        /// Sets the presenters list in the claims principal.
        /// Note: this method automatically excludes duplicate presenters.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="presenters">The presenters to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetPresenters(
            [NotNull] this ClaimsPrincipal principal, [CanBeNull] ImmutableArray<string> presenters)
            => principal.SetClaims(Claims.Private.Presenter, presenters);

        /// <summary>
        /// Sets the presenters list in the claims principal.
        /// Note: this method automatically excludes duplicate presenters.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="presenters">The presenters to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetPresenters(
            [NotNull] this ClaimsPrincipal principal, [CanBeNull] IEnumerable<string> presenters)
            => principal.SetPresenters(presenters?.ToImmutableArray() ?? ImmutableArray.Create<string>());

        /// <summary>
        /// Sets the presenters list in the claims principal.
        /// Note: this method automatically excludes duplicate presenters.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="presenters">The presenters to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetPresenters(
            [NotNull] this ClaimsPrincipal principal, [CanBeNull] params string[] presenters)
            => principal.SetPresenters(presenters?.ToImmutableArray() ?? ImmutableArray.Create<string>());

        /// <summary>
        /// Sets the resources list in the claims principal.
        /// Note: this method automatically excludes duplicate resources.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="resources">The resources to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetResources(
            [NotNull] this ClaimsPrincipal principal, [CanBeNull] ImmutableArray<string> resources)
            => principal.SetClaims(Claims.Private.Resource, resources);

        /// <summary>
        /// Sets the resources list in the claims principal.
        /// Note: this method automatically excludes duplicate resources.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="resources">The resources to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetResources(
            [NotNull] this ClaimsPrincipal principal, [CanBeNull] IEnumerable<string> resources)
            => principal.SetResources(resources?.ToImmutableArray() ?? ImmutableArray.Create<string>());

        /// <summary>
        /// Sets the resources list in the claims principal.
        /// Note: this method automatically excludes duplicate resources.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="resources">The resources to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetResources(
            [NotNull] this ClaimsPrincipal principal, [CanBeNull] params string[] resources)
            => principal.SetResources(resources?.ToImmutableArray() ?? ImmutableArray.Create<string>());

        /// <summary>
        /// Sets the scopes list in the claims principal.
        /// Note: this method automatically excludes duplicate scopes.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="scopes">The scopes to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetScopes(
            [NotNull] this ClaimsPrincipal principal, [CanBeNull] ImmutableArray<string> scopes)
            => principal.SetClaims(Claims.Private.Scope, scopes);

        /// <summary>
        /// Sets the scopes list in the claims principal.
        /// Note: this method automatically excludes duplicate scopes.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="scopes">The scopes to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetScopes(
            [NotNull] this ClaimsPrincipal principal, [CanBeNull] IEnumerable<string> scopes)
            => principal.SetScopes(scopes?.ToImmutableArray() ?? ImmutableArray.Create<string>());

        /// <summary>
        /// Sets the scopes list in the claims principal.
        /// Note: this method automatically excludes duplicate scopes.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="scopes">The scopes to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetScopes(
            [NotNull] this ClaimsPrincipal principal, [CanBeNull] params string[] scopes)
            => principal.SetScopes(scopes?.ToImmutableArray() ?? ImmutableArray.Create<string>());

        /// <summary>
        /// Sets the access token lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="lifetime">The access token lifetime to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetAccessTokenLifetime([NotNull] this ClaimsPrincipal principal, TimeSpan? lifetime)
            => principal.SetClaim(Claims.Private.AccessTokenLifetime, lifetime?.TotalSeconds.ToString(CultureInfo.InvariantCulture));

        /// <summary>
        /// Sets the authorization code lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="lifetime">The authorization code lifetime to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetAuthorizationCodeLifetime([NotNull] this ClaimsPrincipal principal, TimeSpan? lifetime)
            => principal.SetClaim(Claims.Private.AuthorizationCodeLifetime, lifetime?.TotalSeconds.ToString(CultureInfo.InvariantCulture));

        /// <summary>
        /// Sets the device code lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="lifetime">The device code lifetime to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetDeviceCodeLifetime([NotNull] this ClaimsPrincipal principal, TimeSpan? lifetime)
            => principal.SetClaim(Claims.Private.DeviceCodeLifetime, lifetime?.TotalSeconds.ToString(CultureInfo.InvariantCulture));

        /// <summary>
        /// Sets the identity token lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="lifetime">The identity token lifetime to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetIdentityTokenLifetime([NotNull] this ClaimsPrincipal principal, TimeSpan? lifetime)
            => principal.SetClaim(Claims.Private.IdentityTokenLifetime, lifetime?.TotalSeconds.ToString(CultureInfo.InvariantCulture));

        /// <summary>
        /// Sets the refresh token lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="lifetime">The refresh token lifetime to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetRefreshTokenLifetime([NotNull] this ClaimsPrincipal principal, TimeSpan? lifetime)
            => principal.SetClaim(Claims.Private.RefreshTokenLifetime, lifetime?.TotalSeconds.ToString(CultureInfo.InvariantCulture));

        /// <summary>
        /// Sets the user code lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="lifetime">The user code lifetime to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetUserCodeLifetime([NotNull] this ClaimsPrincipal principal, TimeSpan? lifetime)
            => principal.SetClaim(Claims.Private.UserCodeLifetime, lifetime?.TotalSeconds.ToString(CultureInfo.InvariantCulture));

        /// <summary>
        /// Sets the internal authorization identifier associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="identifier">The unique identifier to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetAuthorizationId([NotNull] this ClaimsPrincipal principal, string identifier)
            => principal.SetClaim(Claims.Private.AuthorizationId, identifier);

        /// <summary>
        /// Sets the internal token identifier associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="identifier">The unique identifier to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetTokenId([NotNull] this ClaimsPrincipal principal, string identifier)
            => principal.SetClaim(Claims.Private.TokenId, identifier);

        /// <summary>
        /// Sets the token type associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="type">The token type to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetTokenType([NotNull] this ClaimsPrincipal principal, string type)
            => principal.SetClaim(Claims.Private.TokenType, type);

        private static IEnumerable<string> GetValues(string source, char[] separators)
        {
            Debug.Assert(!string.IsNullOrEmpty(source), SR.GetResourceString(SR.ID5000));
            Debug.Assert(separators?.Length != 0, SR.GetResourceString(SR.ID5001));

            foreach (var element in new StringTokenizer(source, separators))
            {
                var segment = Trim(element, separators);
                if (segment.Length == 0)
                {
                    continue;
                }

                yield return segment.Value;
            }

            yield break;
        }

        private static bool HasValue(string source, string value, char[] separators)
        {
            if (string.IsNullOrEmpty(source))
            {
                return false;
            }

            Debug.Assert(!string.IsNullOrEmpty(value), SR.GetResourceString(SR.ID5002));
            Debug.Assert(separators?.Length != 0, SR.GetResourceString(SR.ID5001));

            foreach (var element in new StringTokenizer(source, separators))
            {
                var segment = Trim(element, separators);
                if (segment.Length == 0)
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
            Debug.Assert(separators?.Length != 0, SR.GetResourceString(SR.ID5001));

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
            Debug.Assert(separators?.Length != 0, SR.GetResourceString(SR.ID5001));

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
            Debug.Assert(separators?.Length != 0, SR.GetResourceString(SR.ID5001));

            return TrimEnd(TrimStart(segment, separators), separators);
        }

        private static bool IsSeparator(char character, char[] separators)
        {
            Debug.Assert(separators?.Length != 0, SR.GetResourceString(SR.ID5001));

            for (var index = 0; index < separators.Length; index++)
            {
                if (character == separators[index])
                {
                    return true;
                }
            }

            return false;
        }

        private static TimeSpan? GetLifetime(ClaimsPrincipal principal, string type)
        {
            if (principal == null)
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
    }
}

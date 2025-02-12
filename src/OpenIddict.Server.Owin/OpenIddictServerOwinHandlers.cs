/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Extensions;
using Owin;
using static OpenIddict.Server.Owin.OpenIddictServerOwinConstants;
using Properties = OpenIddict.Server.Owin.OpenIddictServerOwinConstants.Properties;

namespace OpenIddict.Server.Owin;

[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictServerOwinHandlers
{
    public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
        /*
         * Top-level request processing:
         */
        ResolveRequestUri.Descriptor,
        ValidateTransportSecurityRequirement.Descriptor,
        ValidateHostHeader.Descriptor,

        /*
         * Challenge processing:
         */
        ResolveHostChallengeProperties.Descriptor,
        AttachHostChallengeError.Descriptor,

        /*
         * Sign-in processing:
         */
        ResolveHostSignInProperties.Descriptor,

        /*
         * Sign-out processing:
         */
        ResolveHostSignOutProperties.Descriptor,

        .. Authentication.DefaultHandlers,
        .. Device.DefaultHandlers,
        .. Discovery.DefaultHandlers,
        .. Exchange.DefaultHandlers,
        .. Introspection.DefaultHandlers,
        .. Revocation.DefaultHandlers,
        .. Session.DefaultHandlers,
        .. UserInfo.DefaultHandlers
    ]);

    /// <summary>
    /// Contains the logic responsible for resolving the request URI from the OWIN environment.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ResolveRequestUri : IOpenIddictServerHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ResolveRequestUri>()
                .SetOrder(int.MinValue + 50_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessRequestContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // OpenIddict supports both absolute and relative URIs for all its endpoints, but only absolute
            // URIs can be properly canonicalized by the BCL System.Uri class (e.g './path/../' is normalized
            // to './' once the URI is fully constructed). At this stage of the request processing, rejecting
            // requests that lack the host information (e.g because HTTP/1.0 was used and no Host header was
            // sent by the HTTP client) is not desirable as it would affect all requests, including requests
            // that are not meant to be handled by OpenIddict itself. To avoid that, a fake host is temporarily
            // used to build an absolute base URI and a request URI that will be used to determine whether the
            // received request matches one of the URIs assigned to an OpenIddict endpoint. If the request
            // is later handled by OpenIddict, an additional check will be made to require the Host header.

            (context.BaseUri, context.RequestUri) = request.Host switch
            {
                { Value.Length: > 0 } host => (
                    BaseUri: new Uri(request.Scheme + Uri.SchemeDelimiter + host + request.PathBase, UriKind.Absolute),
                    RequestUri: request.Uri),

                { Value: null or { Length: 0 } } => (
                    BaseUri: new UriBuilder
                    {
                        Scheme = request.Scheme,
                        Path = request.PathBase.ToUriComponent()
                    }.Uri,
                    RequestUri: new UriBuilder
                    {
                        Scheme = request.Scheme,
                        Path = (request.PathBase + request.Path).ToUriComponent(),
                        Query = request.QueryString.ToUriComponent()
                    }.Uri)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting OpenID Connect requests that don't use transport security.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ValidateTransportSecurityRequirement : IOpenIddictServerHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireOwinRequest>()
                .AddFilter<RequireTransportSecurityRequirementEnabled>()
                .UseSingletonHandler<ValidateTransportSecurityRequirement>()
                .SetOrder(InferEndpointType.Descriptor.Order + 250)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessRequestContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // Don't require that transport security be used if the request is not handled by OpenIddict.
            if (context.EndpointType is not OpenIddictServerEndpointType.Unknown && !request.IsSecure)
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2083),
                    uri: SR.FormatID8000(SR.ID2083));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the Host header extracted from the HTTP header.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ValidateHostHeader : IOpenIddictServerHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ValidateHostHeader>()
                .SetOrder(ValidateTransportSecurityRequirement.Descriptor.Order + 250)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessRequestContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // Don't require that the request host be present if the request is not handled by OpenIddict.
            if (context.EndpointType is not OpenIddictServerEndpointType.Unknown &&
                string.IsNullOrEmpty(request.Host.Value))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2081(Headers.Host),
                    uri: SR.FormatID8000(SR.ID2081));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the context-specific properties and parameters stored in the
    /// OWIN authentication properties specified by the application that triggered the challenge operation.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ResolveHostChallengeProperties : IOpenIddictServerHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ResolveHostChallengeProperties>()
                .SetOrder(ValidateChallengeDemand.Descriptor.Order - 500)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName!);
            if (properties is not { Dictionary.Count: > 0 })
            {
                return default;
            }

            // Note: unlike ASP.NET Core, OWIN's AuthenticationProperties doesn't offer a strongly-typed
            // dictionary that allows flowing parameters while preserving their original types. To allow
            // returning custom parameters, the OWIN host allows using AuthenticationProperties.Dictionary
            // but requires suffixing the properties that are meant to be used as parameters using a special
            // suffix that indicates that the property is public and determines its actual representation.
            foreach (var property in properties.Dictionary)
            {
                var (name, value) = property.Key switch
                {
                    // If the property ends with #string, represent it as a string parameter.
                    string key when key.EndsWith(PropertyTypes.String, StringComparison.OrdinalIgnoreCase) => (
                        Name: key[..^PropertyTypes.String.Length],
                        Value: new OpenIddictParameter(property.Value)),

                    // If the property ends with #boolean, return it as a boolean parameter.
                    string key when key.EndsWith(PropertyTypes.Boolean, StringComparison.OrdinalIgnoreCase) => (
                        Name: key[..^PropertyTypes.Boolean.Length],
                        Value: new OpenIddictParameter(bool.Parse(property.Value))),

                    // If the property ends with #integer, return it as an integer parameter.
                    string key when key.EndsWith(PropertyTypes.Integer, StringComparison.OrdinalIgnoreCase) => (
                        Name: key[..^PropertyTypes.Integer.Length],
                        Value: new OpenIddictParameter(long.Parse(property.Value, CultureInfo.InvariantCulture))),

                    // If the property ends with #json, return it as a JSON parameter.
                    string key when key.EndsWith(PropertyTypes.Json, StringComparison.OrdinalIgnoreCase) => (
                        Name: key[..^PropertyTypes.Json.Length],
                        Value: new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(property.Value))),

                    _ => default
                };

                if (!string.IsNullOrEmpty(name))
                {
                    context.Parameters[name] = value;
                }

                else
                {
                    context.Properties[property.Key] = property.Value;
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the error details using the OWIN authentication properties.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class AttachHostChallengeError : IOpenIddictServerHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<AttachHostChallengeError>()
                .SetOrder(AttachDefaultChallengeError.Descriptor.Order - 500)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName!);
            if (properties is not null)
            {
                context.Response.Error = GetProperty(properties, Properties.Error);
                context.Response.ErrorDescription = GetProperty(properties, Properties.ErrorDescription);
                context.Response.ErrorUri = GetProperty(properties, Properties.ErrorUri);
                context.Response.Scope = GetProperty(properties, Properties.Scope);
            }

            return default;

            static string? GetProperty(AuthenticationProperties properties, string name)
                => properties.Dictionary.TryGetValue(name, out string? value) ? value : null;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the context-specific properties and parameters stored in the
    /// OWIN authentication properties specified by the application that triggered the sign-in operation.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ResolveHostSignInProperties : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ResolveHostSignInProperties>()
                .SetOrder(ValidateSignInDemand.Descriptor.Order - 500)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName!);
            if (properties is not { Dictionary.Count: > 0 })
            {
                return default;
            }

            // Note: unlike ASP.NET Core, OWIN's AuthenticationProperties doesn't offer a strongly-typed
            // dictionary that allows flowing parameters while preserving their original types. To allow
            // returning custom parameters, the OWIN host allows using AuthenticationProperties.Dictionary
            // but requires suffixing the properties that are meant to be used as parameters using a special
            // suffix that indicates that the property is public and determines its actual representation.
            foreach (var property in properties.Dictionary)
            {
                var (name, value) = property.Key switch
                {
                    // If the property ends with #string, represent it as a string parameter.
                    string key when key.EndsWith(PropertyTypes.String, StringComparison.OrdinalIgnoreCase) => (
                        Name: key[..^PropertyTypes.String.Length],
                        Value: new OpenIddictParameter(property.Value)),

                    // If the property ends with #boolean, return it as a boolean parameter.
                    string key when key.EndsWith(PropertyTypes.Boolean, StringComparison.OrdinalIgnoreCase) => (
                        Name: key[..^PropertyTypes.Boolean.Length],
                        Value: new OpenIddictParameter(bool.Parse(property.Value))),

                    // If the property ends with #integer, return it as an integer parameter.
                    string key when key.EndsWith(PropertyTypes.Integer, StringComparison.OrdinalIgnoreCase) => (
                        Name: key[..^PropertyTypes.Integer.Length],
                        Value: new OpenIddictParameter(long.Parse(property.Value, CultureInfo.InvariantCulture))),

                    // If the property ends with #json, return it as a JSON parameter.
                    string key when key.EndsWith(PropertyTypes.Json, StringComparison.OrdinalIgnoreCase) => (
                        Name: key[..^PropertyTypes.Json.Length],
                        Value: new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(property.Value))),

                    _ => default
                };

                if (!string.IsNullOrEmpty(name))
                {
                    context.Parameters[name] = value;
                }

                else
                {
                    context.Properties[property.Key] = property.Value;
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the context-specific properties and parameters stored in the
    /// OWIN authentication properties specified by the application that triggered the sign-out operation.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ResolveHostSignOutProperties : IOpenIddictServerHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ResolveHostSignOutProperties>()
                .SetOrder(ValidateSignOutDemand.Descriptor.Order - 500)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName!);
            if (properties is not { Dictionary.Count: > 0 })
            {
                return default;
            }

            // Note: unlike ASP.NET Core, OWIN's AuthenticationProperties doesn't offer a strongly-typed
            // dictionary that allows flowing parameters while preserving their original types. To allow
            // returning custom parameters, the OWIN host allows using AuthenticationProperties.Dictionary
            // but requires suffixing the properties that are meant to be used as parameters using a special
            // suffix that indicates that the property is public and determines its actual representation.
            foreach (var property in properties.Dictionary)
            {
                var (name, value) = property.Key switch
                {
                    // If the property ends with #string, represent it as a string parameter.
                    string key when key.EndsWith(PropertyTypes.String, StringComparison.OrdinalIgnoreCase) => (
                        Name: key[..^PropertyTypes.String.Length],
                        Value: new OpenIddictParameter(property.Value)),

                    // If the property ends with #boolean, return it as a boolean parameter.
                    string key when key.EndsWith(PropertyTypes.Boolean, StringComparison.OrdinalIgnoreCase) => (
                        Name: key[..^PropertyTypes.Boolean.Length],
                        Value: new OpenIddictParameter(bool.Parse(property.Value))),

                    // If the property ends with #integer, return it as an integer parameter.
                    string key when key.EndsWith(PropertyTypes.Integer, StringComparison.OrdinalIgnoreCase) => (
                        Name: key[..^PropertyTypes.Integer.Length],
                        Value: new OpenIddictParameter(long.Parse(property.Value, CultureInfo.InvariantCulture))),

                    // If the property ends with #json, return it as a JSON parameter.
                    string key when key.EndsWith(PropertyTypes.Json, StringComparison.OrdinalIgnoreCase) => (
                        Name: key[..^PropertyTypes.Json.Length],
                        Value: new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(property.Value))),

                    _ => default
                };

                if (!string.IsNullOrEmpty(name))
                {
                    context.Parameters[name] = value;
                }

                else
                {
                    context.Properties[property.Key] = property.Value;
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting OpenID Connect requests from GET HTTP requests.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ExtractGetRequest<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ExtractGetRequest<TContext>>()
                .SetOrder(ValidateTransportSecurityRequirement.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            if (string.Equals(request.Method, "GET", StringComparison.OrdinalIgnoreCase))
            {
                context.Transaction.Request = new OpenIddictRequest(request.Query);
            }

            else
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6137), request.Method);

                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2084),
                    uri: SR.FormatID8000(SR.ID2084));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting OpenID Connect requests from GET or POST HTTP requests.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ExtractGetOrPostRequest<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ExtractGetOrPostRequest<TContext>>()
                .SetOrder(ExtractGetRequest<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            if (string.Equals(request.Method, "GET", StringComparison.OrdinalIgnoreCase))
            {
                context.Transaction.Request = new OpenIddictRequest(request.Query);
            }

            else if (string.Equals(request.Method, "POST", StringComparison.OrdinalIgnoreCase))
            {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization for more information.
                if (string.IsNullOrEmpty(request.ContentType))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6138), Headers.ContentType);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2081(Headers.ContentType),
                        uri: SR.FormatID8000(SR.ID2081));

                    return;
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6139), Headers.ContentType, request.ContentType);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2082(Headers.ContentType),
                        uri: SR.FormatID8000(SR.ID2082));

                    return;
                }

                context.Transaction.Request = new OpenIddictRequest(await request.ReadFormAsync());
            }

            else
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6137), request.Method);

                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2084),
                    uri: SR.FormatID8000(SR.ID2084));

                return;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting OpenID Connect requests from POST HTTP requests.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ExtractPostRequest<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ExtractPostRequest<TContext>>()
                .SetOrder(ExtractGetOrPostRequest<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            if (string.Equals(request.Method, "POST", StringComparison.OrdinalIgnoreCase))
            {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization for more information.
                if (string.IsNullOrEmpty(request.ContentType))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6138), Headers.ContentType);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2081(Headers.ContentType),
                        uri: SR.FormatID8000(SR.ID2081));

                    return;
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6139), Headers.ContentType, request.ContentType);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2082(Headers.ContentType),
                        uri: SR.FormatID8000(SR.ID2082));

                    return;
                }

                context.Transaction.Request = new OpenIddictRequest(await request.ReadFormAsync());
            }

            else
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6137), request.Method);

                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2084),
                    uri: SR.FormatID8000(SR.ID2084));

                return;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the authentication method used by the client application.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ValidateClientAuthenticationMethod<TContext> : IOpenIddictServerHandler<TContext>
        where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ValidateClientAuthenticationMethod<TContext>>()
                .SetOrder(ExtractPostRequest<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // Reject requests that use client_secret_post if support was explicitly disabled in the options.
            if (!string.IsNullOrEmpty(context.Transaction.Request.ClientSecret) &&
                !context.Options.ClientAuthenticationMethods.Contains(ClientAuthenticationMethods.ClientSecretPost))
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6227), ClientAuthenticationMethods.ClientSecretPost);

                context.Reject(
                    error: Errors.InvalidClient,
                    description: SR.FormatID2174(ClientAuthenticationMethods.ClientSecretPost),
                    uri: SR.FormatID8000(SR.ID2174));

                return default;
            }

            // Reject requests that use client_secret_basic if support was explicitly disabled in the options.
            var header = request.Headers[Headers.Authorization];
            if (!string.IsNullOrEmpty(header) && header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase) &&
                !context.Options.ClientAuthenticationMethods.Contains(ClientAuthenticationMethods.ClientSecretBasic))
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6227, ClientAuthenticationMethods.ClientSecretBasic));

                context.Reject(
                    error: Errors.InvalidClient,
                    description: SR.FormatID2174(ClientAuthenticationMethods.ClientSecretBasic),
                    uri: SR.FormatID8000(SR.ID2174));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting client credentials from the standard HTTP Authorization header.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ExtractBasicAuthenticationCredentials<TContext> : IOpenIddictServerHandler<TContext>
        where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ExtractBasicAuthenticationCredentials<TContext>>()
                .SetOrder(ValidateClientAuthenticationMethod<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            var header = request.Headers[Headers.Authorization];
            if (string.IsNullOrEmpty(header) || !header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                return default;
            }

            // At this point, reject requests that use multiple client authentication methods.
            // See https://tools.ietf.org/html/rfc6749#section-2.3 for more information.
            if (!string.IsNullOrEmpty(context.Transaction.Request.ClientAssertion) ||
                !string.IsNullOrEmpty(context.Transaction.Request.ClientSecret))
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6140));

                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2087),
                    uri: SR.FormatID8000(SR.ID2087));

                return default;
            }

            try
            {
                var value = header["Basic ".Length..].Trim();
                var data = Encoding.ASCII.GetString(Convert.FromBase64String(value));

                var index = data.IndexOf(':');
                if (index < 0)
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2055),
                        uri: SR.FormatID8000(SR.ID2055));

                    return default;
                }

                // Attach the basic authentication credentials to the request message.
                context.Transaction.Request.ClientId = UnescapeDataString(data[..index]);
                context.Transaction.Request.ClientSecret = UnescapeDataString(data[(index + 1)..]);

                return default;
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2055),
                    uri: SR.FormatID8000(SR.ID2055));

                return default;
            }

            static string? UnescapeDataString(string data)
            {
                if (string.IsNullOrEmpty(data))
                {
                    return null;
                }

                return Uri.UnescapeDataString(data.Replace("+", "%20"));
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting an access token from the standard HTTP Authorization header.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ExtractAccessToken<TContext> : IOpenIddictServerHandler<TContext>
        where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ExtractAccessToken<TContext>>()
                .SetOrder(ExtractBasicAuthenticationCredentials<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            var header = request.Headers[Headers.Authorization];
            if (string.IsNullOrEmpty(header) || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return default;
            }

            // Attach the access token to the request message.
            context.Transaction.Request.AccessToken = header["Bearer ".Length..];

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for enabling the pass-through mode for the received request.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class EnablePassthroughMode<TContext, TFilter> : IOpenIddictServerHandler<TContext>
        where TContext : BaseRequestContext
        where TFilter : IOpenIddictServerHandlerFilter<TContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .AddFilter<TFilter>()
                .UseSingletonHandler<EnablePassthroughMode<TContext, TFilter>>()
                .SetOrder(int.MaxValue - 100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            switch (context.EndpointType)
            {
                // When authorization request caching is enabled and the request doesn't contain a
                // request_uri yet, do not enable the pass-through mode to allow OpenIddict to trigger
                // a sign-in operation that will generate and attach a request token to the parameters.
                case OpenIddictServerEndpointType.Authorization when
                    context.Options.EnableAuthorizationRequestCaching &&
                    string.IsNullOrEmpty(context.Transaction.Request?.RequestUri):
                    return default;

                // When end session request caching is enabled and the request doesn't contain a
                // request_uri yet, do not enable the pass-through mode to allow OpenIddict to trigger
                // a sign-in operation that will generate and attach a request token to the parameters.
                case OpenIddictServerEndpointType.EndSession when
                    context.Options.EnableEndSessionRequestCaching &&
                    string.IsNullOrEmpty(context.Transaction.Request?.RequestUri):
                    return default;

            }

            context.SkipRequest();
            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching an appropriate HTTP status code.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class AttachHttpResponseCode<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<AttachHttpResponseCode<TContext>>()
                .SetOrder(100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            response.StatusCode = (context.EndpointType, context.Transaction.Response.Error) switch
            {
                // Note: for pushed authorization responses, the returned HTTP status code MUST be 201.
                // See https://datatracker.ietf.org/doc/html/rfc9126#section-2.2 for more information.
                (OpenIddictServerEndpointType.PushedAuthorization, null or { Length: 0 }) => 201,

                // Note: the default code may be replaced by another handler (e.g when doing redirects).
                (_, null or { Length: 0 }) => 200,

                // Unlike other server endpoints, errors returned by the userinfo endpoint follow the same logic as
                // errors returned by API endpoints implementing bearer token authentication and MUST be returned
                // as part of the standard WWW-Authenticate header. For more information, see
                // https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError.
                (OpenIddictServerEndpointType.UserInfo, Errors.InvalidToken       or Errors.MissingToken)      => 401,
                (OpenIddictServerEndpointType.UserInfo, Errors.InsufficientAccess or Errors.InsufficientScope) => 403,

                // When client authentication is made using basic authentication, the authorization server
                // MUST return a 401 response with a valid WWW-Authenticate header containing the HTTP Basic
                // authentication scheme. A similar error MAY be returned even when using client_secret_post.
                // To simplify the logic, a 401 response with the Basic scheme is returned for invalid_client
                // errors, even if credentials were specified in the form, as allowed by the specification.
                (not OpenIddictServerEndpointType.UserInfo, Errors.InvalidClient) => 401,

                (_, Errors.ServerError) => 500,

                // Note: unless specified otherwise, errors are expected to result in 400 responses.
                // See https://datatracker.ietf.org/doc/html/rfc6749#section-5.2 for more information.
                _ => 400
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching an OWIN response chalenge to the context, if necessary.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class AttachOwinResponseChallenge<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<AttachOwinResponseChallenge<TContext>>()
                .SetOrder(AttachHttpResponseCode<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // OWIN authentication middleware configured to use active authentication (which is the default mode)
            // are known to aggressively intercept 401 responses even if the request is already considered fully
            // handled. In practice, this behavior is often seen with the cookies authentication middleware,
            // that will rewrite the 401 responses returned by OpenIddict and try to redirect the user agent
            // to the login page configured in the options. To prevent this undesirable behavior, an explicit
            // response challenge pointing to a non-existent middleware is manually added to the OWIN context
            // to prevent the active authentication middleware from rewriting OpenIddict's 401 HTTP responses.
            //
            // Note: while 403 responses are generally not intercepted by the built-in OWIN authentication
            // middleware, they are treated the same way as 401 responses to account for custom middleware
            // that may potentially use the same interception logic for both 401 and 403 HTTP responses.
            if (response.StatusCode is 401 or 403 &&
                response.Context.Authentication.AuthenticationResponseChallenge is not { AuthenticationTypes.Length: > 0 })
            {
                response.Context.Authentication.AuthenticationResponseChallenge = new AuthenticationResponseChallenge(
                    authenticationTypes: [null],
                    properties         : response.Context.Authentication.AuthenticationResponseChallenge?.Properties ?? new());
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for suppressing the redirection applied by FormsAuthenticationModule, if necessary.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class SuppressFormsAuthenticationRedirect<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<SuppressFormsAuthenticationRedirect<TContext>>()
                .SetOrder(AttachOwinResponseChallenge<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // Similarly to the automatic authentication mode used by OWIN authentication middleware,
            // the ASP.NET FormsAuthentication module aggressively intercepts 401 responses even if
            // the request has already been fully handled by another component (like OpenIddict).
            // To prevent that, this handler is responsible for suppressing the redirection enforced
            // by FormsAuthenticationModule when the status code was set to 401 (the only status code
            // used by the FormsAuthenticationModule) and the OWIN application is hosted on SystemWeb.
            if (response.StatusCode is 401)
            {
                TrySuppressFormsAuthenticationRedirect(response.Environment);
            }

            return default;

            static void TrySuppressFormsAuthenticationRedirect(IDictionary<string, object> environment)
            {
                // Note: the OWIN host cannot depend on the OWIN SystemWeb package but a direct access
                // to the underlying ASP.NET 4.x context is required to be able to disable the redirection
                // enforced by the FormsAuthentication module. To work around that, the HttpContextBase
                // instance is resolved from the OWIN environment and SuppressFormsAuthenticationRedirect
                // is set to true using a dynamic runtime resolution (that uses reflection under the hood).
                if (environment.TryGetValue("System.Web.HttpContextBase", out dynamic context))
                {
                    try
                    {
                        // Note: the SuppressFormsAuthenticationRedirect property was introduced in ASP.NET 4.5
                        // and thus should always be present, as OpenIddict requires targeting ASP.NET >= 4.6.1.
                        context.Response.SuppressFormsAuthenticationRedirect = true;
                    }

                    catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
                    {
                    }
                }
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the appropriate HTTP response cache headers.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class AttachCacheControlHeader<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<AttachCacheControlHeader<TContext>>()
                .SetOrder(SuppressFormsAuthenticationRedirect<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // Prevent the response from being cached.
            response.Headers[Headers.CacheControl] = "no-store";
            response.Headers[Headers.Pragma] = "no-cache";
            response.Headers[Headers.Expires] = "Thu, 01 Jan 1970 00:00:00 GMT";

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching errors details to the WWW-Authenticate header.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class AttachWwwAuthenticateHeader<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
    {
        private readonly IOptionsMonitor<OpenIddictServerOwinOptions> _options;

        public AttachWwwAuthenticateHeader(IOptionsMonitor<OpenIddictServerOwinOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<AttachWwwAuthenticateHeader<TContext>>()
                .SetOrder(AttachCacheControlHeader<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            if (string.IsNullOrEmpty(context.Transaction.Response.Error))
            {
                return default;
            }

            var scheme = (context.EndpointType, context.Transaction.Response.Error) switch
            {
                // Unlike other server endpoints, errors returned by the userinfo endpoint follow the same
                // logic as errors returned by API endpoints implementing bearer token authentication and
                // MUST be returned as part of the standard WWW-Authenticate header. For more information,
                // see https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError.
                (OpenIddictServerEndpointType.UserInfo, _) => Schemes.Bearer,

                // When client authentication is made using basic authentication, the authorization server
                // MUST return a 401 response with a valid WWW-Authenticate header containing the HTTP Basic
                // authentication scheme. A similar error MAY be returned even when using client_secret_post.
                // To simplify the logic, a 401 response with the Basic scheme is returned for invalid_client
                // errors, even if credentials were specified in the form, as allowed by the specification.
                (_, Errors.InvalidClient) => Schemes.Basic,

                // For all other errors, don't return a WWW-Authenticate header and return server errors
                // as formatted JSON responses, as required by the OAuth 2.0 base specification.
                _ => null
            };

            if (string.IsNullOrEmpty(scheme))
            {
                return default;
            }

            var parameters = new Dictionary<string, string>(StringComparer.Ordinal);

            // If a realm was configured in the options, attach it to the parameters.
            if (_options.CurrentValue.Realm is string { Length: > 0 } realm)
            {
                parameters[Parameters.Realm] = realm;
            }

            foreach (var parameter in context.Transaction.Response.GetParameters())
            {
                // Note: the error details are only included if the error was not caused by a missing token, as recommended
                // by the OAuth 2.0 bearer specification: https://tools.ietf.org/html/rfc6750#section-3.1.
                if (context.Transaction.Response.Error is Errors.MissingToken &&
                    parameter.Key is Parameters.Error            or
                                     Parameters.ErrorDescription or
                                     Parameters.ErrorUri)
                {
                    continue;
                }

                // Ignore values that can't be represented as unique strings.
                var value = (string?) parameter.Value;
                if (string.IsNullOrEmpty(value))
                {
                    continue;
                }

                parameters[parameter.Key] = value;
            }

            var builder = new StringBuilder(scheme);

            foreach (var parameter in parameters)
            {
                builder.Append(' ');
                builder.Append(parameter.Key);
                builder.Append('=');
                builder.Append('"');
                builder.Append(parameter.Value.Replace("\"", "\\\""));
                builder.Append('"');
                builder.Append(',');
            }

            // If the WWW-Authenticate header ends with a comma, remove it.
            if (builder[^1] == ',')
            {
                builder.Remove(builder.Length - 1, 1);
            }

            response.Headers.Append(Headers.WwwAuthenticate, builder.ToString());

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for processing challenge responses that contain a WWW-Authenticate header.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ProcessChallengeErrorResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ProcessChallengeErrorResponse<TContext>>()
                .SetOrder(500_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // If the response doesn't contain a WWW-Authenticate header, don't return an empty response.
            if (!response.Headers.ContainsKey(Headers.WwwAuthenticate))
            {
                return default;
            }

            context.Logger.LogInformation(SR.GetResourceString(SR.ID6141), context.Transaction.Response);
            context.HandleRequest();

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for processing OpenID Connect responses that must be returned as JSON.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ProcessJsonResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
    {
        private readonly IOptionsMonitor<OpenIddictServerOwinOptions> _options;

        public ProcessJsonResponse(IOptionsMonitor<OpenIddictServerOwinOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ProcessJsonResponse<TContext>>()
                .SetOrder(ProcessChallengeErrorResponse<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            context.Logger.LogInformation(SR.GetResourceString(SR.ID6142), context.Transaction.Response);

            using var stream = new MemoryStream();
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                Indented = !_options.CurrentValue.SuppressJsonResponseIndentation
            });

            context.Transaction.Response.WriteTo(writer);
            writer.Flush();

            response.ContentLength = stream.Length;
            response.ContentType = "application/json;charset=UTF-8";

            stream.Seek(offset: 0, loc: SeekOrigin.Begin);
            await stream.CopyToAsync(response.Body, 4096, context.CancellationToken);

            context.HandleRequest();
        }
    }

    /// <summary>
    /// Contains the logic responsible for processing OpenID Connect responses that must be handled by another
    /// middleware in the pipeline at a later stage (e.g an ASP.NET MVC action or a NancyFX module).
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ProcessPassthroughErrorResponse<TContext, TFilter> : IOpenIddictServerHandler<TContext>
        where TContext : BaseRequestContext
        where TFilter : IOpenIddictServerHandlerFilter<TContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .AddFilter<RequireErrorPassthroughEnabled>()
                .AddFilter<TFilter>()
                .UseSingletonHandler<ProcessPassthroughErrorResponse<TContext, TFilter>>()
                .SetOrder(ProcessJsonResponse<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

            if (string.IsNullOrEmpty(context.Transaction.Response.Error))
            {
                return default;
            }

            // Don't return the state originally sent by the client application.
            context.Transaction.Response.State = null;

            context.SkipRequest();

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for processing OpenID Connect responses that must be returned as plain-text.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ProcessLocalErrorResponse<TContext> : IOpenIddictServerHandler<TContext>
        where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ProcessLocalErrorResponse<TContext>>()
                .SetOrder(ProcessPassthroughErrorResponse<TContext, IOpenIddictServerHandlerFilter<TContext>>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            if (string.IsNullOrEmpty(context.Transaction.Response.Error))
            {
                return;
            }

            // Don't return the state originally sent by the client application.
            context.Transaction.Response.State = null;

            context.Logger.LogInformation(SR.GetResourceString(SR.ID6143), context.Transaction.Response);

            using var stream = new MemoryStream();
            using var writer = new StreamWriter(stream);

            foreach (var parameter in context.Transaction.Response.GetParameters())
            {
                // Ignore null or empty parameters, including JSON
                // objects that can't be represented as strings.
                var value = (string?) parameter.Value;
                if (string.IsNullOrEmpty(value))
                {
                    continue;
                }

                writer.Write(parameter.Key);
                writer.Write(':');
                writer.Write(value);
                writer.WriteLine();
            }

            writer.Flush();

            response.ContentLength = stream.Length;
            response.ContentType = "text/plain;charset=UTF-8";

            stream.Seek(offset: 0, loc: SeekOrigin.Begin);
            await stream.CopyToAsync(response.Body, 4096, context.CancellationToken);

            context.HandleRequest();
        }
    }

    /// <summary>
    /// Contains the logic responsible for processing OpenID Connect responses that don't specify any parameter.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public sealed class ProcessEmptyResponse<TContext> : IOpenIddictServerHandler<TContext>
        where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ProcessEmptyResponse<TContext>>()
                .SetOrder(int.MaxValue - 100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.Logger.LogInformation(SR.GetResourceString(SR.ID6145));
            context.HandleRequest();

            return default;
        }
    }
}

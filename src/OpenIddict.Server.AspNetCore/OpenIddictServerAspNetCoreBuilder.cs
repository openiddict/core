/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.AspNetCore;
using Microsoft.Extensions.Caching.Distributed;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure
/// the OpenIddict server ASP.NET Core integration.
/// </summary>
public sealed class OpenIddictServerAspNetCoreBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictServerAspNetCoreBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictServerAspNetCoreBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Amends the default OpenIddict server ASP.NET Core configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictServerAspNetCoreBuilder Configure(Action<OpenIddictServerAspNetCoreOptions> configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Disables the transport security requirement (HTTPS).
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictServerAspNetCoreBuilder DisableTransportSecurityRequirement()
        => Configure(options => options.DisableTransportSecurityRequirement = true);

    /// <summary>
    /// Enables the pass-through mode for the OpenID Connect authorization endpoint.
    /// When the pass-through mode is used, OpenID Connect requests are initially handled by OpenIddict.
    /// Once validated, the rest of the request processing pipeline is invoked, so that OpenID Connect requests
    /// can be handled at a later stage (in a custom middleware or in a MVC controller, for instance).
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictServerAspNetCoreBuilder EnableAuthorizationEndpointPassthrough()
        => Configure(options => options.EnableAuthorizationEndpointPassthrough = true);

    /// <summary>
    /// Enables the pass-through mode for the OpenID Connect end session endpoint.
    /// When the pass-through mode is used, OpenID Connect requests are initially handled by OpenIddict.
    /// Once validated, the rest of the request processing pipeline is invoked, so that OpenID Connect requests
    /// can be handled at a later stage (in a custom middleware or in a MVC controller, for instance).
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictServerAspNetCoreBuilder EnableEndSessionEndpointPassthrough()
        => Configure(options => options.EnableEndSessionEndpointPassthrough = true);

    /// <summary>
    /// Enables the pass-through mode for the OpenID Connect end-user verification endpoint.
    /// When the pass-through mode is used, OpenID Connect requests are initially handled by OpenIddict.
    /// Once validated, the rest of the request processing pipeline is invoked, so that OpenID Connect requests
    /// can be handled at a later stage (in a custom middleware or in a MVC controller, for instance).
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictServerAspNetCoreBuilder EnableEndUserVerificationEndpointPassthrough()
        => Configure(options => options.EnableEndUserVerificationEndpointPassthrough = true);

    /// <summary>
    /// Enables error pass-through support, so that the rest of the request processing pipeline is
    /// automatically invoked when returning an error from the interactive authorization and end session endpoints.
    /// When this option is enabled, special logic must be added to these actions to handle errors, that can be
    /// retrieved using <see cref="OpenIddictServerAspNetCoreHelpers.GetOpenIddictServerResponse(HttpContext)"/>.
    /// </summary>
    /// <remarks>
    /// Important: the error pass-through mode cannot be used when the status code pages integration is enabled.
    /// </remarks>
    /// <returns>The <see cref="OpenIddictServerAspNetCoreBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerAspNetCoreBuilder EnableErrorPassthrough()
        => Configure(options => options.EnableErrorPassthrough = true);

    /// <summary>
    /// Enables the pass-through mode for the OpenID Connect token endpoint.
    /// When the pass-through mode is used, OpenID Connect requests are initially handled by OpenIddict.
    /// Once validated, the rest of the request processing pipeline is invoked, so that OpenID Connect requests
    /// can be handled at a later stage (in a custom middleware or in a MVC controller, for instance).
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictServerAspNetCoreBuilder EnableTokenEndpointPassthrough()
        => Configure(options => options.EnableTokenEndpointPassthrough = true);

    /// <summary>
    /// Enables the pass-through mode for the OpenID Connect userinfo endpoint.
    /// When the pass-through mode is used, OpenID Connect requests are initially handled by OpenIddict.
    /// Once validated, the rest of the request processing pipeline is invoked, so that OpenID Connect requests
    /// can be handled at a later stage (in a custom middleware or in a MVC controller, for instance).
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictServerAspNetCoreBuilder EnableUserInfoEndpointPassthrough()
        => Configure(options => options.EnableUserInfoEndpointPassthrough = true);

    /// <summary>
    /// Enables authorization request caching, so that authorization requests
    /// are automatically stored in the distributed cache, which allows flowing
    /// large payloads across requests. Enabling this option is recommended
    /// when using external authentication providers or when large GET or POST
    /// OpenID Connect authorization requests support is required.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerAspNetCoreBuilder"/> instance.</returns>
    [Obsolete("This method is obsolete and will be removed in a future version.")]
    public OpenIddictServerAspNetCoreBuilder EnableAuthorizationRequestCaching()
    {
        Services.Configure<OpenIddictServerOptions>(options => options.EnableAuthorizationRequestCaching = true);

        return this;
    }

    /// <summary>
    /// Enables end session request caching, so that end session requests
    /// are automatically stored in the distributed cache.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerAspNetCoreBuilder"/> instance.</returns>
    [Obsolete("This method is obsolete and will be removed in a future version.")]
    public OpenIddictServerAspNetCoreBuilder EnableEndSessionRequestCaching()
    {
        Services.Configure<OpenIddictServerOptions>(options => options.EnableEndSessionRequestCaching = true);

        return this;
    }

    /// <summary>
    /// Enables status code pages integration support. Once enabled, errors
    /// generated by the interactive endpoints can be handled by ASP.NET Core.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictServerAspNetCoreBuilder EnableStatusCodePagesIntegration()
        => Configure(options => options.EnableStatusCodePagesIntegration = true);

    /// <summary>
    /// Suppresses indentation for the JSON responses returned by the ASP.NET Core host.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictServerAspNetCoreBuilder SuppressJsonResponseIndentation()
        => Configure(options => options.SuppressJsonResponseIndentation = true);

    /// <summary>
    /// Sets the realm returned to the caller as part of the WWW-Authenticate header.
    /// </summary>
    /// <param name="realm">The realm.</param>
    /// <returns>The <see cref="OpenIddictServerAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictServerAspNetCoreBuilder SetRealm(string realm)
    {
        if (string.IsNullOrEmpty(realm))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0107), nameof(realm));
        }

        return Configure(options => options.Realm = realm);
    }

    /// <summary>
    /// Sets the caching policy used by the authorization endpoint.
    /// Note: the specified policy is only used when caching is explicitly enabled.
    /// </summary>
    /// <param name="policy">The caching policy.</param>
    /// <returns>The <see cref="OpenIddictServerAspNetCoreBuilder"/> instance.</returns>
    [Obsolete("This method is obsolete and will be removed in a future version.")]
    public OpenIddictServerAspNetCoreBuilder SetAuthorizationRequestCachingPolicy(DistributedCacheEntryOptions policy)
    {
        if (policy is null)
        {
            throw new ArgumentNullException(nameof(policy));
        }

        return Configure(options => options.AuthorizationRequestCachingPolicy = policy);
    }

    /// <summary>
    /// Sets the caching policy used by the end session endpoint.
    /// Note: the specified policy is only used when caching is explicitly enabled.
    /// </summary>
    /// <param name="policy">The caching policy.</param>
    /// <returns>The <see cref="OpenIddictServerAspNetCoreBuilder"/> instance.</returns>
    [Obsolete("This method is obsolete and will be removed in a future version.")]
    public OpenIddictServerAspNetCoreBuilder SetEndSessionRequestCachingPolicy(DistributedCacheEntryOptions policy)
    {
        if (policy is null)
        {
            throw new ArgumentNullException(nameof(policy));
        }

        return Configure(options => options.EndSessionRequestCachingPolicy = policy);
    }

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => base.Equals(obj);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override string? ToString() => base.ToString();
}

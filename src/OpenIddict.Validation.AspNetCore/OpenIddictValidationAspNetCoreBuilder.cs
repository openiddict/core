﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using OpenIddict.Validation.AspNetCore;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure
/// the OpenIddict validation ASP.NET Core integration.
/// </summary>
public sealed class OpenIddictValidationAspNetCoreBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictValidationAspNetCoreBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictValidationAspNetCoreBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Amends the default OpenIddict validation ASP.NET Core configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictValidationAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictValidationAspNetCoreBuilder Configure(Action<OpenIddictValidationAspNetCoreOptions> configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Prevents OpenIddict from extracting access tokens from the standard "Authorization" header.
    /// </summary>
    /// <remarks>
    /// Disabling access token extraction from the "Authorization" header is NOT recommended.
    /// </remarks>
    /// <returns>The <see cref="OpenIddictValidationAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictValidationAspNetCoreBuilder DisableAccessTokenExtractionFromAuthorizationHeader()
        => Configure(options => options.DisableAccessTokenExtractionFromAuthorizationHeader = true);

    /// <summary>
    /// Prevents OpenIddict from extracting access tokens from the standard "access_token" body form parameter.
    /// </summary>
    /// <returns>The <see cref="OpenIddictValidationAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictValidationAspNetCoreBuilder DisableAccessTokenExtractionFromBodyForm()
        => Configure(options => options.DisableAccessTokenExtractionFromBodyForm = true);

    /// <summary>
    /// Prevents OpenIddict from extracting access tokens from the standard "access_token" query string parameter.
    /// </summary>
    /// <returns>The <see cref="OpenIddictValidationAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictValidationAspNetCoreBuilder DisableAccessTokenExtractionFromQueryString()
        => Configure(options => options.DisableAccessTokenExtractionFromQueryString = true);

    /// <summary>
    /// Sets the realm returned to the caller as part of the WWW-Authenticate header.
    /// </summary>
    /// <param name="realm">The realm.</param>
    /// <returns>The <see cref="OpenIddictValidationAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictValidationAspNetCoreBuilder SetRealm(string realm)
    {
        if (string.IsNullOrEmpty(realm))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0107), nameof(realm));
        }

        return Configure(options => options.Realm = realm);
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

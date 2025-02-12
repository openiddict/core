/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.AspNetCore.DataProtection;
using OpenIddict.Server.DataProtection;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the
/// OpenIddict ASP.NET Core Data Protection integration.
/// </summary>
public sealed class OpenIddictServerDataProtectionBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictServerDataProtectionBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictServerDataProtectionBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Amends the default OpenIddict server ASP.NET Core Data Protection configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerDataProtectionBuilder"/> instance.</returns>
    public OpenIddictServerDataProtectionBuilder Configure(Action<OpenIddictServerDataProtectionOptions> configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Configures OpenIddict to use a specific data protection provider
    /// instead of relying on the default instance provided by the DI container.
    /// </summary>
    /// <param name="provider">The data protection provider used to create token protectors.</param>
    /// <returns>The <see cref="OpenIddictServerDataProtectionBuilder"/> instance.</returns>
    public OpenIddictServerDataProtectionBuilder UseDataProtectionProvider(IDataProtectionProvider provider)
    {
        if (provider is null)
        {
            throw new ArgumentNullException(nameof(provider));
        }

        return Configure(options => options.DataProtectionProvider = provider);
    }

    /// <summary>
    /// Configures OpenIddict to use a specific formatter instead of relying on the default instance.
    /// </summary>
    /// <param name="formatter">The formatter used to read and write tokens.</param>
    /// <returns>The <see cref="OpenIddictServerDataProtectionBuilder"/> instance.</returns>
    public OpenIddictServerDataProtectionBuilder UseFormatter(IOpenIddictServerDataProtectionFormatter formatter)
    {
        if (formatter is null)
        {
            throw new ArgumentNullException(nameof(formatter));
        }

        return Configure(options => options.Formatter = formatter);
    }

    /// <summary>
    /// Configures OpenIddict to use the default token format (JWT) when issuing new access tokens.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerDataProtectionBuilder"/> instance.</returns>
    public OpenIddictServerDataProtectionBuilder PreferDefaultAccessTokenFormat()
        => Configure(options => options.PreferDefaultAccessTokenFormat = true);

    /// <summary>
    /// Configures OpenIddict to use the default token format (JWT) when issuing new authorization codes.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerDataProtectionBuilder"/> instance.</returns>
    public OpenIddictServerDataProtectionBuilder PreferDefaultAuthorizationCodeFormat()
        => Configure(options => options.PreferDefaultAuthorizationCodeFormat = true);

    /// <summary>
    /// Configures OpenIddict to use the default token format (JWT) when issuing new device codes.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerDataProtectionBuilder"/> instance.</returns>
    public OpenIddictServerDataProtectionBuilder PreferDefaultDeviceCodeFormat()
        => Configure(options => options.PreferDefaultDeviceCodeFormat = true);

    /// <summary>
    /// Configures OpenIddict to use the default token format (JWT) when issuing new request tokens.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerDataProtectionBuilder"/> instance.</returns>
    public OpenIddictServerDataProtectionBuilder PreferDefaultRequestTokenFormat()
        => Configure(options => options.PreferDefaultRequestTokenFormat = true);

    /// <summary>
    /// Configures OpenIddict to use the default token format (JWT) when issuing new refresh tokens.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerDataProtectionBuilder"/> instance.</returns>
    public OpenIddictServerDataProtectionBuilder PreferDefaultRefreshTokenFormat()
        => Configure(options => options.PreferDefaultRefreshTokenFormat = true);

    /// <summary>
    /// Configures OpenIddict to use the default token format (JWT) when issuing new user codes.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerDataProtectionBuilder"/> instance.</returns>
    public OpenIddictServerDataProtectionBuilder PreferDefaultUserCodeFormat()
        => Configure(options => options.PreferDefaultUserCodeFormat = true);

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

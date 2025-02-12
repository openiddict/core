/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.DataProtection;

namespace OpenIddict.Server.DataProtection;

/// <summary>
/// Provides various settings needed to configure the OpenIddict
/// ASP.NET Core Data Protection server integration.
/// </summary>
public sealed class OpenIddictServerDataProtectionOptions
{
    /// <summary>
    /// Gets or sets the data protection provider used to create the default
    /// data protectors used by the OpenIddict Data Protection server services.
    /// When this property is set to <see langword="null"/>, the data protection provider
    /// is directly retrieved from the dependency injection container.
    /// </summary>
    public IDataProtectionProvider DataProtectionProvider { get; set; } = default!;

    /// <summary>
    /// Gets or sets the formatter used to read and write Data Protection tokens.
    /// </summary>
    public IOpenIddictServerDataProtectionFormatter Formatter { get; set; }
        = new OpenIddictServerDataProtectionFormatter();

    /// <summary>
    /// Gets or sets a boolean indicating whether the default access token format should be
    /// used when issuing new access tokens. This property is set to <see langword="false"/> by default.
    /// </summary>
    public bool PreferDefaultAccessTokenFormat { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the default authorization code format should be
    /// used when issuing new authorization codes. This property is set to <see langword="false"/> by default.
    /// </summary>
    public bool PreferDefaultAuthorizationCodeFormat { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the default device code format should be
    /// used when issuing new device codes. This property is set to <see langword="false"/> by default.
    /// </summary>
    public bool PreferDefaultDeviceCodeFormat { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the default user code format should be used when issuing
    /// new request tokens. This property is set to <see langword="false"/> by default.
    /// </summary>
    public bool PreferDefaultRequestTokenFormat { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the default refresh token format should be
    /// used when issuing new refresh tokens. This property is set to <see langword="false"/> by default.
    /// </summary>
    public bool PreferDefaultRefreshTokenFormat { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the default user code format should be
    /// used when issuing new user codes. This property is set to <see langword="false"/> by default.
    /// </summary>
    public bool PreferDefaultUserCodeFormat { get; set; }
}

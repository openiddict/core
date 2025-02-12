/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Server;

namespace Microsoft.Extensions.DependencyInjection;

using Microsoft.Extensions.Options;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict server services.
/// </summary>
public static class OpenIddictServerExtensions
{
    /// <summary>
    /// Registers the OpenIddict token server services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public static OpenIddictServerBuilder AddServer(this OpenIddictBuilder builder)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        builder.Services.AddLogging();
        builder.Services.AddOptions();

        builder.Services.TryAddScoped<IOpenIddictServerDispatcher, OpenIddictServerDispatcher>();
        builder.Services.TryAddScoped<IOpenIddictServerFactory, OpenIddictServerFactory>();

        // Register the built-in server event handlers used by the OpenIddict server components.
        // Note: the order used here is not important, as the actual order is set in the options.
        builder.Services.TryAdd(DefaultHandlers.Select(descriptor => descriptor.ServiceDescriptor));

        // Register the built-in filters used by the default OpenIddict server event handlers.
        builder.Services.TryAddSingleton<RequireAccessTokenGenerated>();
        builder.Services.TryAddSingleton<RequireAccessTokenValidated>();
        builder.Services.TryAddSingleton<RequireAuthorizationCodeGenerated>();
        builder.Services.TryAddSingleton<RequireAuthorizationCodeValidated>();
        builder.Services.TryAddSingleton<RequireAuthorizationIdResolved>();
        builder.Services.TryAddSingleton<RequireAuthorizationStorageEnabled>();
        builder.Services.TryAddSingleton<RequireAuthorizationRequest>();
        builder.Services.TryAddSingleton<RequireClientAssertionPrincipal>();
        builder.Services.TryAddSingleton<RequireClientAssertionValidated>();
        builder.Services.TryAddSingleton<RequireClientIdParameter>();
        builder.Services.TryAddSingleton<RequireClientSecretParameter>();
        builder.Services.TryAddSingleton<RequireConfigurationRequest>();
        builder.Services.TryAddSingleton<RequireDegradedModeDisabled>();
        builder.Services.TryAddSingleton<RequireDeviceAuthorizationRequest>();
        builder.Services.TryAddSingleton<RequireDeviceCodeGenerated>();
        builder.Services.TryAddSingleton<RequireDeviceCodeValidated>();
        builder.Services.TryAddSingleton<RequireEndpointPermissionsEnabled>();
        builder.Services.TryAddSingleton<RequireEndSessionRequest>();
        builder.Services.TryAddSingleton<RequireEndUserVerificationRequest>();
        builder.Services.TryAddSingleton<RequireGenericTokenValidated>();
        builder.Services.TryAddSingleton<RequireGrantTypePermissionsEnabled>();
        builder.Services.TryAddSingleton<RequireIdentityTokenGenerated>();
        builder.Services.TryAddSingleton<RequireIdentityTokenValidated>();
        builder.Services.TryAddSingleton<RequireIntrospectionRequest>();
        builder.Services.TryAddSingleton<RequireJsonWebKeySetRequest>();
        builder.Services.TryAddSingleton<RequireJsonWebTokenFormat>();
        builder.Services.TryAddSingleton<RequirePostLogoutRedirectUriParameter>();
        builder.Services.TryAddSingleton<RequirePushedAuthorizationRequest>();
        builder.Services.TryAddSingleton<RequireReferenceAccessTokensEnabled>();
        builder.Services.TryAddSingleton<RequireReferenceRefreshTokensEnabled>();
        builder.Services.TryAddSingleton<RequireRefreshTokenGenerated>();
        builder.Services.TryAddSingleton<RequireRefreshTokenValidated>();
        builder.Services.TryAddSingleton<RequireRequestTokenGenerated>();
        builder.Services.TryAddSingleton<RequireRequestTokenPrincipal>();
        builder.Services.TryAddSingleton<RequireRequestTokenValidated>();
        builder.Services.TryAddSingleton<RequireResponseTypePermissionsEnabled>();
        builder.Services.TryAddSingleton<RequireRevocationRequest>();
        builder.Services.TryAddSingleton<RequireSlidingRefreshTokenExpirationEnabled>();
        builder.Services.TryAddSingleton<RequireScopePermissionsEnabled>();
        builder.Services.TryAddSingleton<RequireScopeValidationEnabled>();
        builder.Services.TryAddSingleton<RequireTokenEntryCreated>();
        builder.Services.TryAddSingleton<RequireTokenIdResolved>();
        builder.Services.TryAddSingleton<RequireTokenLifetimeValidationEnabled>();
        builder.Services.TryAddSingleton<RequireTokenPayloadPersisted>();
        builder.Services.TryAddSingleton<RequireTokenRequest>();
        builder.Services.TryAddSingleton<RequireTokenStorageEnabled>();
        builder.Services.TryAddSingleton<RequireUserCodeGenerated>();
        builder.Services.TryAddSingleton<RequireUserCodeValidated>();
        builder.Services.TryAddSingleton<RequireUserInfoRequest>();

        // Note: TryAddEnumerable() is used here to ensure the initializer is registered only once.
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IPostConfigureOptions<OpenIddictServerOptions>, OpenIddictServerConfiguration>());

        return new OpenIddictServerBuilder(builder.Services);
    }

    /// <summary>
    /// Registers the OpenIddict token server services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the server services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictBuilder"/> instance.</returns>
    public static OpenIddictBuilder AddServer(this OpenIddictBuilder builder, Action<OpenIddictServerBuilder> configuration)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        configuration(builder.AddServer());

        return builder;
    }
}

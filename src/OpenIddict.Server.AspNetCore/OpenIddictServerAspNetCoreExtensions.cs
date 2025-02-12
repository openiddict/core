/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict server services.
/// </summary>
public static class OpenIddictServerAspNetCoreExtensions
{
    /// <summary>
    /// Registers the OpenIddict server services for ASP.NET Core in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerAspNetCoreBuilder"/> instance.</returns>
    public static OpenIddictServerAspNetCoreBuilder UseAspNetCore(this OpenIddictServerBuilder builder)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        builder.Services.AddAuthentication();

        builder.Services.TryAddScoped<OpenIddictServerAspNetCoreHandler>();

        // Register the built-in event handlers used by the OpenIddict ASP.NET Core server components.
        // Note: the order used here is not important, as the actual order is set in the options.
        builder.Services.TryAdd(OpenIddictServerAspNetCoreHandlers.DefaultHandlers.Select(descriptor => descriptor.ServiceDescriptor));

        // Register the built-in filters used by the default OpenIddict ASP.NET Core server event handlers.
#pragma warning disable CS0618
        builder.Services.TryAddSingleton<RequireAuthorizationRequestCachingEnabled>();
        builder.Services.TryAddSingleton<RequireEndSessionRequestCachingEnabled>();
#pragma warning restore CS0618
        builder.Services.TryAddSingleton<RequireAuthorizationEndpointPassthroughEnabled>();
        builder.Services.TryAddSingleton<RequireEndSessionEndpointPassthroughEnabled>();
        builder.Services.TryAddSingleton<RequireErrorPassthroughEnabled>();
        builder.Services.TryAddSingleton<RequireHttpRequest>();
        builder.Services.TryAddSingleton<RequireTransportSecurityRequirementEnabled>();
        builder.Services.TryAddSingleton<RequireStatusCodePagesIntegrationEnabled>();
        builder.Services.TryAddSingleton<RequireTokenEndpointPassthroughEnabled>();
        builder.Services.TryAddSingleton<RequireUserInfoEndpointPassthroughEnabled>();
        builder.Services.TryAddSingleton<RequireVerificationEndpointPassthroughEnabled>();

        // Register the option initializer used by the OpenIddict ASP.NET Core server integration services.
        // Note: TryAddEnumerable() is used here to ensure the initializers are only registered once.
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IConfigureOptions<AuthenticationOptions>, OpenIddictServerAspNetCoreConfiguration>());

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IPostConfigureOptions<AuthenticationOptions>, OpenIddictServerAspNetCoreConfiguration>());

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IConfigureOptions<OpenIddictServerOptions>, OpenIddictServerAspNetCoreConfiguration>());

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IPostConfigureOptions<OpenIddictServerAspNetCoreOptions>, OpenIddictServerAspNetCoreConfiguration>());

        return new OpenIddictServerAspNetCoreBuilder(builder.Services);
    }

    /// <summary>
    /// Registers the OpenIddict server services for ASP.NET Core in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the server services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public static OpenIddictServerBuilder UseAspNetCore(
        this OpenIddictServerBuilder builder, Action<OpenIddictServerAspNetCoreBuilder> configuration)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        configuration(builder.UseAspNetCore());

        return builder;
    }
}

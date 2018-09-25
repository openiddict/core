﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Core;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes extensions allowing to register the OpenIddict core services.
    /// </summary>
    public static class OpenIddictCoreExtensions
    {
        /// <summary>
        /// Registers the OpenIddict core services in the DI container.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictCoreBuilder AddCore([NotNull] this OpenIddictBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Services.AddLogging();
            builder.Services.AddOptions();

            builder.Services.TryAddScoped(typeof(OpenIddictApplicationManager<>));
            builder.Services.TryAddScoped(typeof(OpenIddictAuthorizationManager<>));
            builder.Services.TryAddScoped(typeof(OpenIddictScopeManager<>));
            builder.Services.TryAddScoped(typeof(OpenIddictTokenManager<>));

            builder.Services.TryAddScoped<IOpenIddictApplicationStoreResolver, OpenIddictApplicationStoreResolver>();
            builder.Services.TryAddScoped<IOpenIddictAuthorizationStoreResolver, OpenIddictAuthorizationStoreResolver>();
            builder.Services.TryAddScoped<IOpenIddictScopeStoreResolver, OpenIddictScopeStoreResolver>();
            builder.Services.TryAddScoped<IOpenIddictTokenStoreResolver, OpenIddictTokenStoreResolver>();

            builder.Services.TryAddScoped(provider =>
            {
                var options = provider.GetRequiredService<IOptions<OpenIddictCoreOptions>>().Value;
                if (options.DefaultApplicationType == null)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .Append("No default application entity type was configured in the OpenIddict core options, ")
                        .AppendLine("which generally indicates that no application store was registered in the DI container.")
                        .Append("To register the Entity Framework Core stores, reference the 'OpenIddict.EntityFrameworkCore' ")
                        .Append("package and call 'services.AddOpenIddict().AddCore().UseEntityFrameworkCore()'.")
                        .ToString());
                }

                return (IOpenIddictApplicationManager) provider.GetRequiredService(
                    typeof(OpenIddictApplicationManager<>).MakeGenericType(options.DefaultApplicationType));
            });

            builder.Services.TryAddScoped(provider =>
            {
                var options = provider.GetRequiredService<IOptions<OpenIddictCoreOptions>>().Value;
                if (options.DefaultAuthorizationType == null)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .Append("No default authorization entity type was configured in the OpenIddict core options, ")
                        .AppendLine("which generally indicates that no authorization store was registered in the DI container.")
                        .Append("To register the Entity Framework Core stores, reference the 'OpenIddict.EntityFrameworkCore' ")
                        .Append("package and call 'services.AddOpenIddict().AddCore().UseEntityFrameworkCore()'.")
                        .ToString());
                }

                return (IOpenIddictAuthorizationManager) provider.GetRequiredService(
                    typeof(OpenIddictAuthorizationManager<>).MakeGenericType(options.DefaultAuthorizationType));
            });

            builder.Services.TryAddScoped(provider =>
            {
                var options = provider.GetRequiredService<IOptions<OpenIddictCoreOptions>>().Value;
                if (options.DefaultScopeType == null)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .Append("No default scope entity type was configured in the OpenIddict core options, ")
                        .AppendLine("which generally indicates that no scope store was registered in the DI container.")
                        .Append("To register the Entity Framework Core stores, reference the 'OpenIddict.EntityFrameworkCore' ")
                        .Append("package and call 'services.AddOpenIddict().AddCore().UseEntityFrameworkCore()'.")
                        .ToString());
                }

                return (IOpenIddictScopeManager) provider.GetRequiredService(
                    typeof(OpenIddictScopeManager<>).MakeGenericType(options.DefaultScopeType));
            });

            builder.Services.TryAddScoped(provider =>
            {
                var options = provider.GetRequiredService<IOptions<OpenIddictCoreOptions>>().Value;
                if (options.DefaultTokenType == null)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .Append("No default token entity type was configured in the OpenIddict core options, ")
                        .AppendLine("which generally indicates that no token store was registered in the DI container.")
                        .Append("To register the Entity Framework Core stores, reference the 'OpenIddict.EntityFrameworkCore' ")
                        .Append("package and call 'services.AddOpenIddict().AddCore().UseEntityFrameworkCore()'.")
                        .ToString());
                }

                return (IOpenIddictTokenManager) provider.GetRequiredService(
                    typeof(OpenIddictTokenManager<>).MakeGenericType(options.DefaultTokenType));
            });

            return new OpenIddictCoreBuilder(builder.Services);
        }

        /// <summary>
        /// Registers the OpenIddict core services in the DI container.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <param name="configuration">The configuration delegate used to configure the core services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddCore(
            [NotNull] this OpenIddictBuilder builder,
            [NotNull] Action<OpenIddictCoreBuilder> configuration)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            configuration(builder.AddCore());

            return builder;
        }
    }
}
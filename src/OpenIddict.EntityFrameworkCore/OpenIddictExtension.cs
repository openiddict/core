﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Models;

namespace OpenIddict.EntityFrameworkCore
{
    public class OpenIddictExtension<TApplication, TAuthorization, TScope, TToken, TKey> : IDbContextOptionsExtension
        where TApplication : OpenIddictApplication<TKey, TAuthorization, TToken>, new()
        where TAuthorization : OpenIddictAuthorization<TKey, TApplication, TToken>, new()
        where TScope : OpenIddictScope<TKey>, new()
        where TToken : OpenIddictToken<TKey, TApplication, TAuthorization>, new()
        where TKey : IEquatable<TKey>
    {
        public string LogFragment => null;
        private readonly OpenIddictEntityFrameworkOptions _openIddictEntityFrameworkOptions;

        public OpenIddictExtension(OpenIddictEntityFrameworkOptions openIddictEntityFrameworkOptions)
        {
            _openIddictEntityFrameworkOptions = openIddictEntityFrameworkOptions;
        }

        public bool ApplyServices([NotNull] IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            services.AddSingleton<OpenIddictEntityFrameworkOptions>(_openIddictEntityFrameworkOptions);
            services.AddSingleton<IModelCustomizer, OpenIddictCustomizer<TApplication, TAuthorization, TScope, TToken, TKey>>();

            // Return false to indicate that no database
            // provider was registered by this extension.
            return false;
        }

        public long GetServiceProviderHashCode() => 0;

        public void Validate([NotNull] IDbContextOptions options) { }
    }
}

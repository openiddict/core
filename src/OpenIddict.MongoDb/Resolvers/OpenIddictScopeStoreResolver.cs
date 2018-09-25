﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Reflection;
using System.Text;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.MongoDb.Models;

namespace OpenIddict.MongoDb
{
    /// <summary>
    /// Exposes a method allowing to resolve a scope store.
    /// </summary>
    public class OpenIddictScopeStoreResolver : IOpenIddictScopeStoreResolver
    {
        private readonly IServiceProvider _provider;

        public OpenIddictScopeStoreResolver([NotNull] IServiceProvider provider)
        {
            _provider = provider;
        }

        /// <summary>
        /// Returns a scope store compatible with the specified scope type or throws an
        /// <see cref="InvalidOperationException"/> if no store can be built using the specified type.
        /// </summary>
        /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
        /// <returns>An <see cref="IOpenIddictScopeStore{TScope}"/>.</returns>
        public IOpenIddictScopeStore<TScope> Get<TScope>() where TScope : class
        {
            var store = _provider.GetService<IOpenIddictScopeStore<TScope>>();
            if (store != null)
            {
                return store;
            }

            if (!typeof(OpenIddictScope).IsAssignableFrom(typeof(TScope)))
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The specified scope type is not compatible with the MongoDB stores.")
                    .Append("When enabling the MongoDB stores, make sure you use the built-in 'OpenIddictScope' ")
                    .Append("entity (from the 'OpenIddict.MongoDb.Models' package) or a custom entity ")
                    .Append("that inherits from the 'OpenIddictScope' entity.")
                    .ToString());
            }

            return (IOpenIddictScopeStore<TScope>) _provider.GetRequiredService(
                typeof(OpenIddictScopeStore<>).MakeGenericType(typeof(TScope)));
        }
    }
}

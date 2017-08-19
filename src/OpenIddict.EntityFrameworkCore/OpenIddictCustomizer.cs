﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Models;

namespace OpenIddict.EntityFrameworkCore
{
    /// <summary>
    /// Represents a model customizer able to register the entity sets
    /// required by the OpenIddict stack in an Entity Framework context.
    /// </summary>
    public class OpenIddictCustomizer<TApplication, TAuthorization, TScope, TToken, TKey> : RelationalModelCustomizer
        where TApplication : OpenIddictApplication<TKey, TAuthorization, TToken>, new()
        where TAuthorization : OpenIddictAuthorization<TKey, TApplication, TToken>, new()
        where TScope : OpenIddictScope<TKey>, new()
        where TToken : OpenIddictToken<TKey, TApplication, TAuthorization>, new()
        where TKey : IEquatable<TKey>
    {
        public OpenIddictCustomizer([NotNull] ModelCustomizerDependencies dependencies)
            : base(dependencies)
        {
        }

        public override void Customize([NotNull] ModelBuilder builder, [NotNull] DbContext context)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Register the OpenIddict entity sets.
            builder.UseOpenIddict<TApplication, TAuthorization, TScope, TToken, TKey>();

            base.Customize(builder, context);
        }
    }
}
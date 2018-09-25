﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using System.Text;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.Internal;

namespace Microsoft.Extensions.DependencyInjection
{
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
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public static OpenIddictServerBuilder AddServer([NotNull] this OpenIddictBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Services.AddAuthentication();
            builder.Services.AddDistributedMemoryCache();
            builder.Services.AddLogging();
            builder.Services.AddMemoryCache();
            builder.Services.AddOptions();

            builder.Services.TryAddScoped<IOpenIddictServerEventService, OpenIddictServerEventService>();

            return new OpenIddictServerBuilder(builder.Services);
        }

        /// <summary>
        /// Registers the OpenIddict token server services in the DI container.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <param name="configuration">The configuration delegate used to configure the server services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public static OpenIddictBuilder AddServer(
            [NotNull] this OpenIddictBuilder builder,
            [NotNull] Action<OpenIddictServerBuilder> configuration)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            configuration(builder.AddServer());

            return builder;
        }

        /// <summary>
        /// Registers the OpenIddict server middleware in the ASP.NET Core pipeline.
        /// </summary>
        /// <param name="app">The application builder used to register middleware instances.</param>
        /// <returns>The <see cref="IApplicationBuilder"/>.</returns>
        public static IApplicationBuilder UseOpenIddictServer([NotNull] this IApplicationBuilder app)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            var options = app.ApplicationServices.GetRequiredService<IOptions<OpenIddictServerOptions>>().Value;
            if (options.Provider == null || options.Provider.GetType() != typeof(OpenIddictServerProvider))
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("OpenIddict can only be used with its built-in server provider.")
                    .AppendLine("This error may indicate that 'OpenIddictServerOptions.Provider' was manually set.")
                    .Append("To execute custom request handling logic, consider registering an event handler using ")
                    .Append("the generic 'services.AddOpenIddict().AddServer().AddEventHandler()' method.")
                    .ToString());
            }

            // When no distributed cache has been registered in the options, use the
            // global instance registered in the dependency injection container.
            if (options.Cache == null)
            {
                options.Cache = app.ApplicationServices.GetRequiredService<IDistributedCache>();
            }

            // If OpenIddict was configured to use reference tokens, replace the default access tokens/
            // authorization codes/refresh tokens formats using a specific data protector to ensure
            // that encrypted tokens stored in the database cannot be treated as valid tokens if the
            // reference tokens option is later turned off by the developer.
            if (options.UseReferenceTokens)
            {
                // Note: a default data protection provider is always registered by
                // the OpenID Connect server handler when none is explicitly set but
                // this initializer is registered to be invoked before ASOS' initializer.
                // To ensure the provider property is never null, it's manually set here.
                if (options.DataProtectionProvider == null)
                {
                    options.DataProtectionProvider = app.ApplicationServices.GetDataProtectionProvider();
                }

                if (options.AccessTokenFormat == null)
                {
                    var protector = options.DataProtectionProvider.CreateProtector(
                        nameof(OpenIdConnectServerHandler),
                        nameof(options.AccessTokenFormat),
                        nameof(options.UseReferenceTokens),
                        options.AuthenticationScheme);

                    options.AccessTokenFormat = new TicketDataFormat(protector);
                }

                if (options.AuthorizationCodeFormat == null)
                {
                    var protector = options.DataProtectionProvider.CreateProtector(
                        nameof(OpenIdConnectServerHandler),
                        nameof(options.AuthorizationCodeFormat),
                        nameof(options.UseReferenceTokens),
                        options.AuthenticationScheme);

                    options.AuthorizationCodeFormat = new TicketDataFormat(protector);
                }

                if (options.RefreshTokenFormat == null)
                {
                    var protector = options.DataProtectionProvider.CreateProtector(
                        nameof(OpenIdConnectServerHandler),
                        nameof(options.RefreshTokenFormat),
                        nameof(options.UseReferenceTokens),
                        options.AuthenticationScheme);

                    options.RefreshTokenFormat = new TicketDataFormat(protector);
                }
            }

            // Ensure at least one flow has been enabled.
            if (options.GrantTypes.Count == 0)
            {
                throw new InvalidOperationException("At least one OAuth2/OpenID Connect flow must be enabled.");
            }

            // Ensure the authorization endpoint has been enabled when
            // the authorization code or implicit grants are supported.
            if (!options.AuthorizationEndpointPath.HasValue && (options.GrantTypes.Contains(OpenIddictConstants.GrantTypes.AuthorizationCode) ||
                                                                options.GrantTypes.Contains(OpenIddictConstants.GrantTypes.Implicit)))
            {
                throw new InvalidOperationException("The authorization endpoint must be enabled to use " +
                                                    "the authorization code and implicit flows.");
            }

            // Ensure the token endpoint has been enabled when the authorization code,
            // client credentials, password or refresh token grants are supported.
            if (!options.TokenEndpointPath.HasValue && (options.GrantTypes.Contains(OpenIddictConstants.GrantTypes.AuthorizationCode) ||
                                                        options.GrantTypes.Contains(OpenIddictConstants.GrantTypes.ClientCredentials) ||
                                                        options.GrantTypes.Contains(OpenIddictConstants.GrantTypes.Password) ||
                                                        options.GrantTypes.Contains(OpenIddictConstants.GrantTypes.RefreshToken)))
            {
                throw new InvalidOperationException(
                    "The token endpoint must be enabled to use the authorization code, client credentials, password and refresh token flows.");
            }

            if (options.EnableRequestCaching && options.RequestCachingPolicy == null)
            {
                throw new InvalidOperationException("A caching policy must be specified when enabling request caching.");
            }

            if (options.RevocationEndpointPath.HasValue && options.DisableTokenStorage)
            {
                throw new InvalidOperationException("The revocation endpoint cannot be enabled when token storage is disabled.");
            }

            if (options.UseReferenceTokens && options.DisableTokenStorage)
            {
                throw new InvalidOperationException("Reference tokens cannot be used when disabling token storage.");
            }

            if (options.UseReferenceTokens && options.AccessTokenHandler != null)
            {
                throw new InvalidOperationException("Reference tokens cannot be used when configuring JWT as the access token format.");
            }

            if (options.UseSlidingExpiration && options.DisableTokenStorage && !options.UseRollingTokens)
            {
                throw new InvalidOperationException(
                    "Sliding expiration must be disabled when turning off token storage if rolling tokens are not used.");
            }

            if (options.AccessTokenHandler != null && options.SigningCredentials.Count == 0)
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("At least one signing key must be registered when using JWT as the access token format.")
                    .Append("Consider registering a certificate using 'services.AddOpenIddict().AddServer().AddSigningCertificate()' ")
                    .Append("or 'services.AddOpenIddict().AddServer().AddDevelopmentSigningCertificate()' or call ")
                    .Append("'services.AddOpenIddict().AddServer().AddEphemeralSigningKey()' to use an ephemeral key.")
                    .ToString());
            }

            // Ensure at least one asymmetric signing certificate/key was registered if the implicit flow was enabled.
            if (!options.SigningCredentials.Any(credentials => credentials.Key is AsymmetricSecurityKey) &&
                 options.GrantTypes.Contains(OpenIddictConstants.GrantTypes.Implicit))
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("At least one asymmetric signing key must be registered when enabling the implicit flow.")
                    .Append("Consider registering a certificate using 'services.AddOpenIddict().AddServer().AddSigningCertificate()' ")
                    .Append("or 'services.AddOpenIddict().AddServer().AddDevelopmentSigningCertificate()' or call ")
                    .Append("'services.AddOpenIddict().AddServer().AddEphemeralSigningKey()' to use an ephemeral key.")
                    .ToString());
            }

            // Automatically add the offline_access scope if the refresh token grant has been enabled.
            if (options.GrantTypes.Contains(OpenIddictConstants.GrantTypes.RefreshToken))
            {
                options.Scopes.Add(OpenIddictConstants.Scopes.OfflineAccess);
            }

            return app.UseOpenIdConnectServer(options);
        }
    }
}

/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.AspNetCore;
using Microsoft.Extensions.Options;

namespace OpenIddict.Server.AspNetCore;

/// <summary>
/// Contains a collection of event handler filters commonly used by the ASP.NET Core handlers.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public static class OpenIddictServerAspNetCoreHandlerFilters
{
    /// <summary>
    /// Represents a filter that excludes the associated handlers if authorization request caching was not enabled.
    /// </summary>
    [Obsolete("This filter is obsolete and will be removed in a future version.")]
    public sealed class RequireAuthorizationRequestCachingEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

        public RequireAuthorizationRequestCachingEnabled(IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(_options.CurrentValue.EnableAuthorizationRequestCaching);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the
    /// pass-through mode was not enabled for the authorization endpoint.
    /// </summary>
    public sealed class RequireAuthorizationEndpointPassthroughEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

        public RequireAuthorizationEndpointPassthroughEnabled(IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(_options.CurrentValue.EnableAuthorizationEndpointPassthrough);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if end session request caching was not enabled.
    /// </summary>
    [Obsolete("This filter is obsolete and will be removed in a future version.")]
    public sealed class RequireEndSessionRequestCachingEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

        public RequireEndSessionRequestCachingEnabled(IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(_options.CurrentValue.EnableEndSessionRequestCaching);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the
    /// pass-through mode was not enabled for the end session endpoint.
    /// </summary>
    public sealed class RequireEndSessionEndpointPassthroughEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

        public RequireEndSessionEndpointPassthroughEnabled(IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(_options.CurrentValue.EnableEndSessionEndpointPassthrough);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if error pass-through was not enabled.
    /// </summary>
    public sealed class RequireErrorPassthroughEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

        public RequireErrorPassthroughEnabled(IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(_options.CurrentValue.EnableErrorPassthrough);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no ASP.NET Core request can be found.
    /// </summary>
    public sealed class RequireHttpRequest : IOpenIddictServerHandlerFilter<BaseContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.Transaction.GetHttpRequest() is not null);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if status code pages support was not enabled.
    /// </summary>
    public sealed class RequireStatusCodePagesIntegrationEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

        public RequireStatusCodePagesIntegrationEnabled(IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(_options.CurrentValue.EnableStatusCodePagesIntegration);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the HTTPS requirement was disabled.
    /// </summary>
    public sealed class RequireTransportSecurityRequirementEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

        public RequireTransportSecurityRequirementEnabled(IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!_options.CurrentValue.DisableTransportSecurityRequirement);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the
    /// pass-through mode was not enabled for the authorization endpoint.
    /// </summary>
    public sealed class RequireTokenEndpointPassthroughEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

        public RequireTokenEndpointPassthroughEnabled(IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(_options.CurrentValue.EnableTokenEndpointPassthrough);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the
    /// pass-through mode was not enabled for the userinfo endpoint.
    /// </summary>
    public sealed class RequireUserInfoEndpointPassthroughEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

        public RequireUserInfoEndpointPassthroughEnabled(IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(_options.CurrentValue.EnableUserInfoEndpointPassthrough);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the
    /// pass-through mode was not enabled for the end-user verification endpoint.
    /// </summary>
    public sealed class RequireVerificationEndpointPassthroughEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

        public RequireVerificationEndpointPassthroughEnabled(IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(_options.CurrentValue.EnableEndUserVerificationEndpointPassthrough);
        }
    }
}

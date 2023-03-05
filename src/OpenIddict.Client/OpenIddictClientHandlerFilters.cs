﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.Client;

[EditorBrowsable(EditorBrowsableState.Advanced)]
public static class OpenIddictClientHandlerFilters
{
    /// <summary>
    /// Represents a filter that excludes the associated handlers if no authorization code is validated.
    /// </summary>
    public sealed class RequireAuthorizationCodeValidated : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.ValidateAuthorizationCode);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no backchannel access token is validated.
    /// </summary>
    public sealed class RequireBackchannelAccessTokenValidated : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.ValidateBackchannelAccessToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if backchannel identity token nonce validation was disabled.
    /// </summary>
    public sealed class RequireBackchannelIdentityTokenNonceValidationEnabled : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!context.DisableBackchannelIdentityTokenNonceValidation);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no backchannel identity token principal is available.
    /// </summary>
    public sealed class RequireBackchannelIdentityTokenPrincipal : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.BackchannelIdentityTokenPrincipal is not null);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no backchannel identity token is validated.
    /// </summary>
    public sealed class RequireBackchannelIdentityTokenValidated : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.ValidateBackchannelIdentityToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no client assertion token is generated.
    /// </summary>
    public sealed class RequireClientAssertionTokenGenerated : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.GenerateClientAssertionToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no frontchannel access token is validated.
    /// </summary>
    public sealed class RequireFrontchannelAccessTokenValidated : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.ValidateFrontchannelAccessToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if frontchannel identity token nonce validation was disabled.
    /// </summary>
    public sealed class RequireFrontchannelIdentityTokenNonceValidationEnabled : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!context.DisableFrontchannelIdentityTokenNonceValidation);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no frontchannel identity token principal is available.
    /// </summary>
    public sealed class RequireFrontchannelIdentityTokenPrincipal : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.FrontchannelIdentityTokenPrincipal is not null);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no frontchannel identity token is validated.
    /// </summary>
    public sealed class RequireFrontchannelIdentityTokenValidated : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.ValidateFrontchannelIdentityToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the challenge
    /// doesn't correspond to an authorization code or implicit grant operation.
    /// </summary>
    public sealed class RequireInteractiveGrantType : IOpenIddictClientHandlerFilter<ProcessChallengeContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.GrantType switch
            {
                GrantTypes.AuthorizationCode or GrantTypes.Implicit  => true,
                null when context.ResponseType is ResponseTypes.None => true,
                _ => false
            });
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the selected token format is not JSON Web Token.
    /// </summary>
    public sealed class RequireJsonWebTokenFormat : IOpenIddictClientHandlerFilter<GenerateTokenContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(GenerateTokenContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.TokenFormat is TokenFormats.Jwt);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no login state token is generated.
    /// </summary>
    public sealed class RequireLoginStateTokenGenerated : IOpenIddictClientHandlerFilter<ProcessChallengeContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.GenerateStateToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no logout state token is generated.
    /// </summary>
    public sealed class RequireLogoutStateTokenGenerated : IOpenIddictClientHandlerFilter<ProcessSignOutContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.GenerateStateToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the request is not a post-logout redirection request.
    /// </summary>
    public sealed class RequirePostLogoutRedirectionRequest : IOpenIddictClientHandlerFilter<BaseContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.EndpointType is OpenIddictClientEndpointType.PostLogoutRedirection);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the request is not a redirection request.
    /// </summary>
    public sealed class RequireRedirectionRequest : IOpenIddictClientHandlerFilter<BaseContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.EndpointType is OpenIddictClientEndpointType.Redirection);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no refresh token is validated.
    /// </summary>
    public sealed class RequireRefreshTokenValidated : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.ValidateRefreshToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no state token principal is available.
    /// </summary>
    public sealed class RequireStateTokenPrincipal : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.StateTokenPrincipal is not null);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no state token is validated.
    /// </summary>
    public sealed class RequireStateTokenValidated : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.ValidateStateToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no token entry is created in the database.
    /// </summary>
    public sealed class RequireTokenEntryCreated : IOpenIddictClientHandlerFilter<GenerateTokenContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(GenerateTokenContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.CreateTokenEntry);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no token identifier is resolved from the token.
    /// </summary>
    public sealed class RequireTokenIdResolved : IOpenIddictClientHandlerFilter<ValidateTokenContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ValidateTokenContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!string.IsNullOrEmpty(context.TokenId));
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the token payload is not persisted in the database.
    /// </summary>
    public sealed class RequireTokenPayloadPersisted : IOpenIddictClientHandlerFilter<GenerateTokenContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(GenerateTokenContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.PersistTokenPayload);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no token request is expected to be sent.
    /// </summary>
    public sealed class RequireTokenRequest : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.SendTokenRequest);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if token storage was not enabled.
    /// </summary>
    public sealed class RequireTokenStorageEnabled : IOpenIddictClientHandlerFilter<BaseContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!context.Options.DisableTokenStorage);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no userinfo request is expected to be sent.
    /// </summary>
    public sealed class RequireUserinfoRequest : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.SendUserinfoRequest);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no userinfo token is extracted.
    /// </summary>
    public sealed class RequireUserinfoTokenExtracted : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.ExtractUserinfoToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no userinfo token principal is available.
    /// </summary>
    public sealed class RequireUserinfoTokenPrincipal : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.UserinfoTokenPrincipal is not null);
        }
    }
}

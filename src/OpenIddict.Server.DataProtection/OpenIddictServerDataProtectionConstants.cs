/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server.DataProtection;

public static class OpenIddictServerDataProtectionConstants
{
    public static class Properties
    {
        public const string AccessTokenLifetime = ".access_token_lifetime";
        public const string AuthorizationCodeLifetime = ".authorization_code_lifetime";
        public const string Audiences = ".audiences";
        public const string CodeChallenge = ".code_challenge";
        public const string CodeChallengeMethod = ".code_challenge_method";
        public const string DeviceCodeId = ".device_code_id";
        public const string DeviceCodeLifetime = ".device_code_lifetime";
        public const string HostProperties = ".host_properties";
        public const string Expires = ".expires";
        public const string IdentityTokenLifetime = ".identity_token_lifetime";
        public const string InternalAuthorizationId = ".internal_authorization_id";
        public const string InternalTokenId = ".internal_token_id";
        public const string Issued = ".issued";
        public const string Nonce = ".nonce";
        public const string OriginalRedirectUri = ".original_redirect_uri";
        public const string Presenters = ".presenters";
        public const string RefreshTokenLifetime = ".refresh_token_lifetime";
        public const string RequestTokenLifetime = ".request_token_lifetime";
        public const string Resources = ".resources";
        public const string Scopes = ".scopes";
        public const string UserCodeLifetime = ".user_code_lifetime";
    }

    public static class Purposes
    {
        public static class Features
        {
            public const string ReferenceTokens = "UseReferenceTokens";
        }

        public static class Formats
        {
            public const string AccessToken = "AccessTokenFormat";
            public const string AuthorizationCode = "AuthorizationCodeFormat";
            public const string DeviceCode = "DeviceCodeFormat";
            public const string RequestToken = "RequestTokenFormat";
            public const string RefreshToken = "RefreshTokenFormat";
            public const string UserCode = "UserCodeFormat";
        }

        public static class Handlers
        {
            public const string Server = "OpenIdConnectServerHandler";
        }

        public static class Schemes
        {
            public const string Server = "ASOS";
        }
    }
}

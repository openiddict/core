/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using OpenIddict.Extensions;
using static OpenIddict.Client.OpenIddictClientHandlers.Discovery;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

public static partial class OpenIddictClientWebIntegrationHandlers
{
    public static class Discovery
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * Configuration response handling:
             */
            AmendIssuer.Descriptor,
            AmendGrantTypes.Descriptor,
            AmendCodeChallengeMethods.Descriptor,
            AmendScopes.Descriptor,
            AmendClientAuthenticationMethods.Descriptor,
            AmendEndpoints.Descriptor
        ]);

        /// <summary>
        /// Contains the logic responsible for amending the issuer for the providers that require it.
        /// </summary>
        public sealed class AmendIssuer : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<AmendIssuer>()
                    .SetOrder(ValidateIssuer.Descriptor.Order - 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.Response[Metadata.Issuer] = context.Registration.ProviderType switch
                {
                    // Note: the server configuration metadata returned by the Microsoft Account special tenants
                    // uses "https://login.microsoftonline.com/{tenantid}/v2.0" as the issuer to indicate that
                    // the issued identity tokens will have a dynamic issuer claim whose value will be resolved
                    // based on the client identity. As required by RFC8414, OpenIddict would automatically reject
                    // such responses as the issuer wouldn't match the expected value. To work around that, the
                    // issuer is replaced by this handler to always use a static value (e.g "common" or "consumers").
                    //
                    // For more information about the special tenants supported by Microsoft Account/Entra ID, see
                    // https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc#find-your-apps-openid-configuration-document-uri.
                    ProviderTypes.Microsoft when context.Registration.GetMicrosoftSettings() is { Tenant: string tenant } =>
                        string.Equals(tenant, "common",        StringComparison.OrdinalIgnoreCase) ? "https://login.microsoftonline.com/common/v2.0"        :
                        string.Equals(tenant, "consumers",     StringComparison.OrdinalIgnoreCase) ? "https://login.microsoftonline.com/consumers/v2.0"     :
                        string.Equals(tenant, "organizations", StringComparison.OrdinalIgnoreCase) ? "https://login.microsoftonline.com/organizations/v2.0" :
                        context.Response[Metadata.Issuer],

                    // Note: the issuer returned in the Webex server configuration metadata is region-specific and
                    // varies dynamically depending on the location of the client making the discovery request.
                    // Since the returned issuer is not stable, a hardcoded value is used instead.
                    ProviderTypes.Webex => "https://www.webex.com/",

                    _ => context.Response[Metadata.Issuer]
                };

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for amending the supported grant types for the providers that require it.
        /// </summary>
        public sealed class AmendGrantTypes : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<AmendGrantTypes>()
                    .SetOrder(ExtractGrantTypes.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: some providers don't list the grant types they support, which prevents the OpenIddict
                // client from using them (unless they are assumed to be enabled by default, like the
                // authorization code or implicit flows). To work around that, the list of supported grant
                // types is amended to include the known supported types for the providers that require it.

                if (context.Registration.ProviderType is
                    ProviderTypes.Apple    or ProviderTypes.FaceIt or
                    ProviderTypes.LinkedIn or ProviderTypes.QuickBooksOnline)
                {
                    context.Configuration.GrantTypesSupported.Add(GrantTypes.AuthorizationCode);
                    context.Configuration.GrantTypesSupported.Add(GrantTypes.RefreshToken);
                }

                else if (context.Registration.ProviderType is ProviderTypes.Atlassian)
                {
                    context.Configuration.GrantTypesSupported.Add(GrantTypes.AuthorizationCode);
                    context.Configuration.GrantTypesSupported.Add(GrantTypes.Implicit);
                    context.Configuration.GrantTypesSupported.Add(GrantTypes.RefreshToken);
                }

                else if (context.Registration.ProviderType is ProviderTypes.Auth0 or ProviderTypes.Microsoft)
                {
                    context.Configuration.GrantTypesSupported.Add(GrantTypes.AuthorizationCode);
                    context.Configuration.GrantTypesSupported.Add(GrantTypes.ClientCredentials);
                    context.Configuration.GrantTypesSupported.Add(GrantTypes.DeviceCode);
                    context.Configuration.GrantTypesSupported.Add(GrantTypes.Implicit);
                    context.Configuration.GrantTypesSupported.Add(GrantTypes.RefreshToken);
                }

                else if (context.Registration.ProviderType is
                    ProviderTypes.Cognito or ProviderTypes.EpicGames or ProviderTypes.Salesforce or ProviderTypes.Twitch)
                {
                    context.Configuration.GrantTypesSupported.Add(GrantTypes.AuthorizationCode);
                    context.Configuration.GrantTypesSupported.Add(GrantTypes.ClientCredentials);
                    context.Configuration.GrantTypesSupported.Add(GrantTypes.RefreshToken);
                }

                else if (context.Registration.ProviderType is ProviderTypes.Google)
                {
                    context.Configuration.GrantTypesSupported.Add(GrantTypes.Implicit);
                }

                else if (context.Registration.ProviderType is ProviderTypes.Huawei)
                {
                    context.Configuration.GrantTypesSupported.Add(GrantTypes.AuthorizationCode);
                    context.Configuration.GrantTypesSupported.Add(GrantTypes.ClientCredentials);
                    context.Configuration.GrantTypesSupported.Add(GrantTypes.DeviceCode);
                    context.Configuration.GrantTypesSupported.Add(GrantTypes.RefreshToken);
                }

                else if (context.Registration.ProviderType is
                    ProviderTypes.DocuSign or ProviderTypes.Asana or ProviderTypes.Slack)
                {
                    context.Configuration.GrantTypesSupported.Add(GrantTypes.RefreshToken);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for amending the supported
        /// code challenge methods for the providers that require it.
        /// </summary>
        public sealed class AmendCodeChallengeMethods : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<AmendCodeChallengeMethods>()
                    .SetOrder(ExtractCodeChallengeMethods.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Some providers support Proof Key for Code Exchange but don't list any supported code
                // challenge method in the server configuration metadata. To ensure the OpenIddict client
                // always uses Proof Key for Code Exchange for these providers, the supported methods
                // are manually added to the list of supported code challenge methods by this handler.

                if (context.Registration.ProviderType is
                    ProviderTypes.Adobe  or ProviderTypes.Autodesk  or
                    ProviderTypes.FaceIt or ProviderTypes.Microsoft or ProviderTypes.Zoho)
                {
                    context.Configuration.CodeChallengeMethodsSupported.Add(CodeChallengeMethods.Plain);
                    context.Configuration.CodeChallengeMethodsSupported.Add(CodeChallengeMethods.Sha256);
                }

                else if (context.Registration.ProviderType is ProviderTypes.DocuSign or ProviderTypes.Salesforce)
                {
                    context.Configuration.CodeChallengeMethodsSupported.Add(CodeChallengeMethods.Sha256);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for amending the supported scopes for the providers that require it.
        /// </summary>
        public sealed class AmendScopes : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<AmendScopes>()
                    .SetOrder(ExtractScopes.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Atlassian includes the "openid" scope in its server configuration but doesn't currently allow
                // requesting it. To prevent an error from being returned, OpenID Connect support is disabled.
                if (context.Registration.ProviderType is ProviderTypes.Atlassian)
                {
                    context.Configuration.ScopesSupported.Remove(Scopes.OpenId);
                }

                // DocuSign supports OpenID Connect but doesn't format the "openid" scope using the standard casing.
                // To ensure DocuSign is not treated as an OAuth 2.0-only provider, the invalid "OpenId" scope is
                // removed from the list and the "openid" value is added to indicate OpenID Connect is supported.
                else if (context.Registration.ProviderType is ProviderTypes.DocuSign)
                {
                    context.Configuration.ScopesSupported.Remove("OpenId");
                    context.Configuration.ScopesSupported.Add(Scopes.OpenId);
                }

                // While it is a recommended node, these providers don't include "scopes_supported" in their
                // configuration and thus are treated as OAuth 2.0-only providers by the OpenIddict client.
                // To avoid that, the "openid" scope is manually added to indicate OpenID Connect is supported.
                else if (context.Registration.ProviderType is ProviderTypes.EpicGames or ProviderTypes.Xero or ProviderTypes.EveOnline)
                {
                    context.Configuration.ScopesSupported.Add(Scopes.OpenId);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for amending the supported client
        /// authentication methods for the providers that require it.
        /// </summary>
        public sealed class AmendClientAuthenticationMethods : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<AmendClientAuthenticationMethods>()
                    .SetOrder(ExtractTokenEndpointClientAuthenticationMethods.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Apple implements a non-standard client authentication method for its endpoints that
                // is inspired by the standard private_key_jwt method but doesn't use the standard
                // client_assertion/client_assertion_type parameters. Instead, the client assertion
                // must be sent as a "dynamic" client secret using client_secret_post. Since the logic
                // is the same as private_key_jwt, the configuration is amended to assume Apple supports
                // private_key_jwt and an event handler is responsible for populating the client_secret
                // parameter using the client assertion once it has been generated by OpenIddict.
                if (context.Registration.ProviderType is ProviderTypes.Apple)
                {
                    context.Configuration.RevocationEndpointAuthMethodsSupported.Add(
                        ClientAuthenticationMethods.PrivateKeyJwt);

                    context.Configuration.TokenEndpointAuthMethodsSupported.Add(
                        ClientAuthenticationMethods.PrivateKeyJwt);
                }

                // Atlassian doesn't return a "revocation_endpoint_auth_methods_supported" node in its
                // server configuration but only supports the "client_secret_post" authentication method.
                else if (context.Registration.ProviderType is ProviderTypes.Atlassian)
                {
                    context.Configuration.RevocationEndpointAuthMethodsSupported.Add(
                        ClientAuthenticationMethods.ClientSecretPost);
                }

                // Google doesn't properly implement the device authorization grant, doesn't support
                // basic client authentication for the device authorization endpoint and returns
                // a generic "invalid_request" error when using "client_secret_basic" instead of
                // sending the client identifier in the request form. To work around this limitation,
                // "client_secret_post" is listed as the only supported client authentication method.
                else if (context.Registration.ProviderType is ProviderTypes.Google)
                {
                    context.Configuration.DeviceAuthorizationEndpointAuthMethodsSupported.Clear();
                    context.Configuration.DeviceAuthorizationEndpointAuthMethodsSupported.Add(
                        ClientAuthenticationMethods.ClientSecretPost);
                }

                // Huawei doesn't support sending the client credentials using basic authentication when
                // using the device authorization grant, making basic authentication the default authentication
                // method. To work around this compliance issue, "client_secret_post" is manually added here.
                else if (context.Registration.ProviderType is ProviderTypes.Huawei)
                {
                    context.Configuration.DeviceAuthorizationEndpointAuthMethodsSupported.Add(
                        ClientAuthenticationMethods.ClientSecretPost);
                }

                // LinkedIn doesn't support sending the client credentials using basic authentication but
                // doesn't return a "token_endpoint_auth_methods_supported" node containing alternative
                // authentication methods, making basic authentication the default authentication method.
                // To work around this compliance issue, "client_secret_post" is manually added here.
                else if (context.Registration.ProviderType is ProviderTypes.LinkedIn)
                {
                    context.Configuration.TokenEndpointAuthMethodsSupported.Add(
                        ClientAuthenticationMethods.ClientSecretPost);
                }

                // Pro Santé Connect lists private_key_jwt as a supported client authentication method but
                // only supports client_secret_basic/client_secret_post and tls_client_auth and plans to
                // remove secret-based authentication support in late 2024 to force clients to use mTLS.
                else if (context.Registration.ProviderType is ProviderTypes.ProSantéConnect)
                {
                    context.Configuration.DeviceAuthorizationEndpointAuthMethodsSupported.Remove(
                        ClientAuthenticationMethods.PrivateKeyJwt);

                    context.Configuration.IntrospectionEndpointAuthMethodsSupported.Remove(
                        ClientAuthenticationMethods.PrivateKeyJwt);

                    context.Configuration.RevocationEndpointAuthMethodsSupported.Remove(
                        ClientAuthenticationMethods.PrivateKeyJwt);

                    context.Configuration.TokenEndpointAuthMethodsSupported.Remove(
                        ClientAuthenticationMethods.PrivateKeyJwt);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for amending the endpoint URIs for the providers that require it.
        /// </summary>
        public sealed class AmendEndpoints : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<AmendEndpoints>()
                    .SetOrder(int.MaxValue - 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // While Atlassian implements an OpenID Connect userinfo endpoint, using it requires
                // requesting the "openid" scope, which isn't allowed yet. To work around this
                // limitation, the userinfo endpoint is replaced by the generic /me endpoint URI.
                if (context.Registration.ProviderType is ProviderTypes.Atlassian)
                {
                    context.Configuration.UserInfoEndpoint = new Uri("https://api.atlassian.com/me", UriKind.Absolute);
                }

                // While Auth0 exposes an OpenID Connect-compliant end session endpoint, its address is not returned
                // as part of the configuration document. To ensure RP-initiated logout is supported with Auth0,
                // "end_session_endpoint" is manually computed using the issuer URI and added to the configuration.
                else if (context.Registration.ProviderType is ProviderTypes.Auth0)
                {
                    context.Configuration.EndSessionEndpoint ??= OpenIddictHelpers.CreateAbsoluteUri(
                        context.Registration.Issuer, "oidc/logout");
                }

                // While Huawei supports OpenID Connect discovery, the configuration
                // document doesn't return the address of the device authorization endpoint.
                // To work around that, the endpoint URI is manually added here.
                else if (context.Registration.ProviderType is ProviderTypes.Huawei)
                {
                    context.Configuration.DeviceAuthorizationEndpoint =
                        new Uri("https://oauth-login.cloud.huawei.com/oauth2/v3/device/code", UriKind.Absolute);
                }

                // While it exposes a standard OpenID Connect userinfo endpoint, Orange France doesn't list it
                // in its configuration document. To work around that, the endpoint URI is manually added here.
                else if (context.Registration.ProviderType is ProviderTypes.OrangeFrance)
                {
                    context.Configuration.UserInfoEndpoint ??=
                        new Uri("https://api.orange.com/openidconnect/fr/v1/userinfo", UriKind.Absolute);
                }

                // While PayPal supports OpenID Connect discovery, the configuration document returned
                // by the sandbox environment always contains the production endpoints, which would
                // prevent the OpenIddict integration from working properly when using the sandbox mode.
                // To work around that, the endpoints are manually overridden when this environment is used.
                else if (context.Registration.ProviderType is ProviderTypes.PayPal &&
                    context.Registration.GetPayPalSettings() is { Environment: PayPal.Environments.Sandbox })
                {
                    context.Configuration.AuthorizationEndpoint =
                        new Uri("https://www.sandbox.paypal.com/signin/authorize", UriKind.Absolute);
                    context.Configuration.JsonWebKeySetUri =
                        new Uri("https://api-m.sandbox.paypal.com/v1/oauth2/certs", UriKind.Absolute);
                    context.Configuration.RevocationEndpoint =
                        new Uri("https://api-m.sandbox.paypal.com/v1/oauth2/revoke", UriKind.Absolute);
                    context.Configuration.TokenEndpoint =
                        new Uri("https://api-m.sandbox.paypal.com/v1/oauth2/token", UriKind.Absolute);
                    context.Configuration.UserInfoEndpoint =
                        new Uri("https://api-m.sandbox.paypal.com/v1/oauth2/token/userinfo", UriKind.Absolute);
                }

                return default;
            }
        }
    }
}

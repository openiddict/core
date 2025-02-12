using System.Globalization;
using System.Text;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;
using Scriban;

namespace OpenIddict.Client.WebIntegration.Generators;

[Generator]
public sealed class OpenIddictClientWebIntegrationGenerator : ISourceGenerator
{
    public void Execute(GeneratorExecutionContext context)
    {
        var file = context.AdditionalFiles.Select(file => file.Path)
            .Where(path => string.Equals(Path.GetFileName(path), "OpenIddictClientWebIntegrationProviders.xml"))
            .SingleOrDefault();

        if (string.IsNullOrEmpty(file))
        {
            return;
        }

        var document = XDocument.Load(file, LoadOptions.None);

        context.AddSource(
            "OpenIddictClientWebIntegrationBuilder.generated.cs",
            SourceText.From(GenerateBuilderMethods(document), Encoding.UTF8));

        context.AddSource(
            "OpenIddictClientWebIntegrationConfiguration.generated.cs",
            SourceText.From(GenerateConfigurationClasses(document), Encoding.UTF8));

        context.AddSource(
            "OpenIddictClientWebIntegrationConstants.generated.cs",
            SourceText.From(GenerateConstants(document), Encoding.UTF8));

        context.AddSource(
            "OpenIddictClientWebIntegrationHelpers.generated.cs",
            SourceText.From(GenerateHelpers(document), Encoding.UTF8));

        context.AddSource(
            "OpenIddictClientWebIntegrationSettings.generated.cs",
            SourceText.From(GenerateSettings(document), Encoding.UTF8));

        static string GenerateBuilderMethods(XDocument document)
        {
            var template = Template.Parse(@"#nullable enable
#pragma warning disable CS0618

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Client;
using OpenIddict.Client.WebIntegration;
using OpenIddict.Extensions;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace Microsoft.Extensions.DependencyInjection;

public sealed partial class OpenIddictClientWebIntegrationBuilder
{
    {{~ for provider in providers ~}}
    /// <summary>
    /// Adds a new {{ provider.display_name }} client registration.
    {{~ if provider.documentation ~}}
    /// For more information, read <see href=""{{ provider.documentation }}"">the documentation</see>.
    {{~ end ~}}
    /// </summary>
    /// <param name=""configuration"">The delegate used to configure the OpenIddict/{{ provider.display_name }} options.</param>
    /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder""/> instance.</returns>
    {{~ if provider.obsolete ~}}
    [Obsolete(""This provider is no longer supported and will be removed in a future version."")]
    {{~ end ~}}
    public OpenIddictClientWebIntegrationBuilder Add{{ provider.name }}(Action<OpenIddictClientWebIntegrationBuilder.{{ provider.name }}> configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        Services.Configure<OpenIddictClientOptions>(options =>
        {
            var registration = new OpenIddictClientRegistration
            {
                ProviderSettings = new OpenIddictClientWebIntegrationSettings.{{ provider.name }}(),
                ProviderType = ProviderTypes.{{ provider.name }}
            };

            configuration(new OpenIddictClientWebIntegrationBuilder.{{ provider.name }}(registration));

            options.Registrations.Add(registration);
        });

        return this;
    }
    {{~ end ~}}

    {{~ for provider in providers ~}}
    /// <summary>
    /// Exposes the necessary methods required to configure the {{ provider.display_name }} integration.
    /// </summary>
    {{~ if provider.obsolete ~}}
    [Obsolete(""This provider is no longer supported and will be removed in a future version."")]
    {{~ end ~}}
    public sealed partial class {{ provider.name }}
    {
        /// <summary>
        /// Initializes a new instance of <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/>.
        /// </summary>
        /// <param name=""registration"">The client registration.</param>
        public {{ provider.name }}(OpenIddictClientRegistration registration)
            => Registration = registration ?? throw new ArgumentNullException(nameof(registration));

        /// <summary>
        /// Gets the client registration.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public OpenIddictClientRegistration Registration { get; }

        /// <summary>
        /// Adds one or more client authentication methods to the list of client authentication methods that can be negotiated for this provider.
        /// </summary>
        /// <param name=""methods"">The client authentication methods.</param>
        /// <remarks>Note: explicitly configuring the allowed client authentication methods is NOT recommended in most cases.</remarks>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public {{ provider.name }} AddClientAuthenticationMethods(params string[] methods)
        {
            if (methods is null)
            {
                throw new ArgumentNullException(nameof(methods));
            }

            return Set(registration => registration.ClientAuthenticationMethods.UnionWith(methods));
        }

        /// <summary>
        /// Adds one or more code challenge methods to the list of code challenge methods that can be negotiated for this provider.
        /// </summary>
        /// <param name=""methods"">The code challenge methods.</param>
        /// <remarks>Note: explicitly configuring the allowed code challenge methods is NOT recommended in most cases.</remarks>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public {{ provider.name }} AddCodeChallengeMethods(params string[] methods)
        {
            if (methods is null)
            {
                throw new ArgumentNullException(nameof(methods));
            }

            return Set(registration => registration.CodeChallengeMethods.UnionWith(methods));
        }

        /// <summary>
        /// Adds one or more grant types to the list of grant types that can be negotiated for this provider.
        /// </summary>
        /// <param name=""types"">The grant types.</param>
        /// <remarks>Note: explicitly configuring the allowed grant types is NOT recommended in most cases.</remarks>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public {{ provider.name }} AddGrantTypes(params string[] types)
        {
            if (types is null)
            {
                throw new ArgumentNullException(nameof(types));
            }

            return Set(registration => registration.GrantTypes.UnionWith(types));
        }

        /// <summary>
        /// Adds one or more response modes to the list of response modes that can be negotiated for this provider.
        /// </summary>
        /// <param name=""modes"">The response modes.</param>
        /// <remarks>Note: explicitly configuring the allowed response modes is NOT recommended in most cases.</remarks>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public {{ provider.name }} AddResponseModes(params string[] modes)
        {
            if (modes is null)
            {
                throw new ArgumentNullException(nameof(modes));
            }

            return Set(registration => registration.ResponseModes.UnionWith(modes));
        }

        /// <summary>
        /// Adds one or more response types to the list of response types that can be negotiated for this provider.
        /// </summary>
        /// <param name=""types"">The response types.</param>
        /// <remarks>Note: explicitly configuring the allowed response types is NOT recommended in most cases.</remarks>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public {{ provider.name }} AddResponseTypes(params string[] types)
        {
            if (types is null)
            {
                throw new ArgumentNullException(nameof(types));
            }

            return Set(registration => registration.ResponseTypes.UnionWith(types));
        }

        /// <summary>
        /// Adds one or more scopes to the list of requested scopes, if applicable.
        /// </summary>
        /// <param name=""scopes"">The scopes.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} AddScopes(params string[] scopes)
        {
            if (scopes is null)
            {
                throw new ArgumentNullException(nameof(scopes));
            }

            return Set(registration => registration.Scopes.UnionWith(scopes));
        }

        /// <summary>
        /// Disables pushed authorization requests for this client registration. When pushed authorization
        /// requests are disabled, PAR is not used by the OpenIddict client, even if the remote authorization
        /// server exposes a pushed authorization endpoint. If the authorization server requires using PAR,
        /// an exception is automatically thrown when starting an interactive authentication challenge.
        /// </summary>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} DisablePushedAuthorizationRequests()
            => Set(registration => registration.DisablePushedAuthorizationRequests = true);

        /// <summary>
        /// Sets the issuer that will be attached to the <see cref=""Claim""/>
        /// instances created by the OpenIddict client stack for this provider.
        /// </summary>
        /// <param name=""issuer"">The claims issuer.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} SetClaimsIssuer(string issuer)
        {
            if (string.IsNullOrEmpty(issuer))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(issuer));
            }

            return Set(registration => registration.ClaimsIssuer = issuer);
        }

        /// <summary>
        /// Sets the provider name.
        /// </summary>
        /// <param name=""name"">The provider name.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} SetProviderName(string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(name));
            }

            return Set(registration => registration.ProviderName = name);
        }

        /// <summary>
        /// Sets the provider display name.
        /// </summary>
        /// <param name=""name"">The provider display name.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} SetProviderDisplayName(string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(name));
            }

            return Set(registration => registration.ProviderDisplayName = name);
        }

        /// <summary>
        /// Sets the registration identifier.
        /// </summary>
        /// <param name=""identifier"">The registration identifier.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} SetRegistrationId(string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(identifier));
            }

            return Set(registration => registration.RegistrationId = identifier);
        }

        /// <summary>
        /// Sets the client identifier.
        /// </summary>
        /// <param name=""identifier"">The client identifier.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} SetClientId(string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(identifier));
            }

            return Set(registration => registration.ClientId = identifier);
        }

        /// <summary>
        /// Sets the client secret, if applicable.
        /// </summary>
        /// <param name=""secret"">The client secret.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} SetClientSecret(string secret)
        {
            if (string.IsNullOrEmpty(secret))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0125), nameof(secret));
            }

            return Set(registration => registration.ClientSecret = secret);
        }

        /// <summary>
        /// Sets the post-logout redirection URI, if applicable.
        /// </summary>
        /// <remarks>
        /// Note: the post-logout redirection URI is automatically added to
        /// <see cref=""OpenIddictClientOptions.PostLogoutRedirectionEndpointUris""/>.
        /// </remarks>
        /// <param name=""uri"">The post-logout redirection URI.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} SetPostLogoutRedirectUri(Uri uri)
        {
            if (uri is null)
            {
                throw new ArgumentNullException(nameof(uri));
            }

            return Set(registration => registration.PostLogoutRedirectUri = uri);
        }

        /// <summary>
        /// Sets the post-logout redirection URI, if applicable.
        /// </summary>
        /// <remarks>
        /// Note: the post-logout redirection URI is automatically added to
        /// <see cref=""OpenIddictClientOptions.PostLogoutRedirectionEndpointUris""/>.
        /// </remarks>
        /// <param name=""uri"">The post-logout redirection URI.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} SetPostLogoutRedirectUri([StringSyntax(StringSyntaxAttribute.Uri)] string uri)
        {
            if (string.IsNullOrEmpty(uri))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0143), nameof(uri));
            }

            return SetPostLogoutRedirectUri(new Uri(uri, UriKind.RelativeOrAbsolute));
        }

        /// <summary>
        /// Sets the redirection URI, if applicable.
        /// </summary>
        /// <remarks>
        /// Note: the redirection URI is automatically added to
        /// <see cref=""OpenIddictClientOptions.RedirectionEndpointUris""/>.
        /// </remarks>
        /// <param name=""uri"">The redirection URI.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} SetRedirectUri(Uri uri)
        {
            if (uri is null)
            {
                throw new ArgumentNullException(nameof(uri));
            }

            return Set(registration => registration.RedirectUri = uri);
        }

        /// <summary>
        /// Sets the redirection URI, if applicable.
        /// </summary>
        /// <remarks>
        /// Note: the redirection URI is automatically added to
        /// <see cref=""OpenIddictClientOptions.RedirectionEndpointUris""/>.
        /// </remarks>
        /// <param name=""uri"">The redirection URI.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} SetRedirectUri([StringSyntax(StringSyntaxAttribute.Uri)] string uri)
        {
            if (string.IsNullOrEmpty(uri))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0143), nameof(uri));
            }

            return SetRedirectUri(new Uri(uri, UriKind.RelativeOrAbsolute));
        }

        {{~ for environment in provider.environments ~}}
        /// <summary>
        /// Configures the provider to use the ""{{ environment.name }}"" environment.
        /// </summary>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        public {{ provider.name }} Use{{ environment.name }}Environment()
            => Set(registration => registration.Get{{ provider.name }}Settings().Environment = OpenIddictClientWebIntegrationConstants.{{ provider.name }}.Environments.{{ environment.name }});
        {{~ end ~}}

        {{~ for setting in provider.settings ~}}
        {{~ if setting.collection ~}}
        /// <summary>
        /// Configures {{ setting.description }}.
        /// </summary>
        /// <param name=""{{ setting.parameter_name }}"">{{ setting.description | string.capitalize }}.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        {{~ if setting.obsolete ~}}
        [Obsolete(""This option is no longer supported and will be removed in a future version."")]
        {{~ end ~}}
        public {{ provider.name }} Add{{ setting.property_name }}(params {{ setting.clr_type }}[] {{ setting.parameter_name }})
        {
            if ({{ setting.parameter_name }} is null)
            {
                throw new ArgumentNullException(nameof({{ setting.parameter_name }}));
            }

            return Set(registration => registration.Get{{ provider.name }}Settings().{{ setting.property_name }}.UnionWith({{ setting.parameter_name }}));
        }
        {{~ else if setting.clr_type == 'ECDsaSecurityKey' ~}}
        /// <summary>
        /// Configures {{ setting.description }}.
        /// </summary>
        /// <param name=""{{ setting.parameter_name }}"">{{ setting.description | string.capitalize }}.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        {{~ if setting.obsolete ~}}
        [Obsolete(""This option is no longer supported and will be removed in a future version."")]
        {{~ end ~}}
        public {{ provider.name }} Set{{ setting.property_name }}(ECDsaSecurityKey {{ setting.parameter_name }})
        {
            if ({{ setting.parameter_name }} is null)
            {
                throw new ArgumentNullException(nameof({{ setting.parameter_name }}));
            }

            if ({{ setting.parameter_name }}.PrivateKeyStatus is PrivateKeyStatus.DoesNotExist)
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0055), nameof({{ setting.parameter_name }}));
            }

            return Set(registration => registration.Get{{ provider.name }}Settings().{{ setting.property_name }} = {{ setting.parameter_name }});
        }

#if SUPPORTS_PEM_ENCODED_KEY_IMPORT
        /// <summary>
        /// Configures {{ setting.description }}.
        /// </summary>
        /// <param name=""key"">
        /// The PEM-encoded Elliptic Curve Digital Signature Algorithm (ECDSA) signing key.
        /// </param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        {{~ if setting.obsolete ~}}
        [Obsolete(""This option is no longer supported and will be removed in a future version."")]
        {{~ end ~}}
        public {{ provider.name }} Set{{ setting.property_name }}(string key)
            => Set{{ setting.property_name }}(key.AsMemory());

        /// <summary>
        /// Configures {{ setting.description }}.
        /// </summary>
        /// <param name=""key"">
        /// The PEM-encoded Elliptic Curve Digital Signature Algorithm (ECDSA) signing key.
        /// </param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        {{~ if setting.obsolete ~}}
        [Obsolete(""This option is no longer supported and will be removed in a future version."")]
        {{~ end ~}}
        public {{ provider.name }} Set{{ setting.property_name }}(ReadOnlyMemory<char> key)
            => Set{{ setting.property_name }}(key.Span);

        /// <summary>
        /// Configures {{ setting.description }}.
        /// </summary>
        /// <param name=""key"">
        /// The PEM-encoded Elliptic Curve Digital Signature Algorithm (ECDSA) signing key.
        /// </param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        {{~ if setting.obsolete ~}}
        [Obsolete(""This option is no longer supported and will be removed in a future version."")]
        {{~ end ~}}
        public {{ provider.name }} Set{{ setting.property_name }}(ReadOnlySpan<char> key)
        {
            if (key.IsEmpty)
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0346), nameof(key));
            }

            var algorithm = OpenIddictHelpers.CreateEcdsaKey();

            try
            {
                algorithm.ImportFromPem(key);
            }

            catch
            {
                algorithm.Dispose();

                throw;
            }

            return Set{{ setting.property_name }}(new ECDsaSecurityKey(algorithm));
        }
#endif
        {{~ else if setting.clr_type == 'Uri' ~}}
        /// <summary>
        /// Configures {{ setting.description }}.
        /// </summary>
        /// <param name=""{{ setting.parameter_name }}"">{{ setting.description | string.capitalize }}.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        {{~ if setting.obsolete ~}}
        [Obsolete(""This option is no longer supported and will be removed in a future version."")]
        {{~ end ~}}
        public {{ provider.name }} Set{{ setting.property_name }}(Uri {{ setting.parameter_name }})
        {
            if ({{ setting.parameter_name }} is null)
            {
                throw new ArgumentNullException(nameof({{ setting.parameter_name }}));
            }

            if (!{{ setting.parameter_name }}.IsAbsoluteUri || OpenIddictHelpers.IsImplicitFileUri({{ setting.parameter_name }}))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof({{ setting.parameter_name }}));
            }

            return Set(registration => registration.Get{{ provider.name }}Settings().{{ setting.property_name }} = {{ setting.parameter_name }});
        }

        /// <summary>
        /// Configures {{ setting.description }}.
        /// </summary>
        /// <param name=""{{ setting.parameter_name }}"">{{ setting.description | string.capitalize }}.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        {{~ if setting.obsolete ~}}
        [Obsolete(""This option is no longer supported and will be removed in a future version."")]
        {{~ end ~}}
        public {{ provider.name }} Set{{ setting.property_name }}(string {{ setting.parameter_name }})
        {
            if (string.IsNullOrEmpty({{ setting.parameter_name }}))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0143), nameof({{ setting.parameter_name }}));
            }

            return Set{{ setting.property_name }}(new Uri({{ setting.parameter_name }}, UriKind.RelativeOrAbsolute));
        }
        {{~ else if setting.clr_type == 'X509Certificate2' ~}}
        /// <summary>
        /// Configures {{ setting.description }}.
        /// </summary>
        /// <param name=""{{ setting.parameter_name }}"">{{ setting.description | string.capitalize }}.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        {{~ if setting.obsolete ~}}
        [Obsolete(""This option is no longer supported and will be removed in a future version."")]
        {{~ end ~}}
        public {{ provider.name }} Set{{ setting.property_name }}(X509Certificate2 {{ setting.parameter_name }})
        {
            if ({{ setting.parameter_name }} is null)
            {
                throw new ArgumentNullException(nameof({{ setting.parameter_name }}));
            }

            if (!{{ setting.parameter_name }}.HasPrivateKey)
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0061), nameof({{ setting.parameter_name }}));
            }

            return Set(registration => registration.Get{{ provider.name }}Settings().{{ setting.property_name }} = {{ setting.parameter_name }});
        }

        /// <summary>
        /// Configures {{ setting.description }}.
        /// </summary>
        /// <param name=""assembly"">The assembly containing the certificate.</param>
        /// <param name=""resource"">The name of the embedded resource.</param>
        /// <param name=""password"">The password used to open the certificate.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        {{~ if setting.obsolete ~}}
        [Obsolete(""This option is no longer supported and will be removed in a future version."")]
        {{~ end ~}}
        public {{ provider.name }} Set{{ setting.property_name }}(Assembly assembly, string resource, string? password)
#if SUPPORTS_EPHEMERAL_KEY_SETS
            // Note: ephemeral key sets are currently not supported on macOS.
            => Set{{ setting.property_name }}(assembly, resource, password, RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ?
                X509KeyStorageFlags.MachineKeySet :
                X509KeyStorageFlags.EphemeralKeySet);
#else
            => Set{{ setting.property_name }}(assembly, resource, password, X509KeyStorageFlags.MachineKeySet);
#endif

        /// <summary>
        /// Configures {{ setting.description }}.
        /// </summary>
        /// <param name=""assembly"">The assembly containing the certificate.</param>
        /// <param name=""resource"">The name of the embedded resource.</param>
        /// <param name=""password"">The password used to open the certificate.</param>
        /// <param name=""flags"">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        {{~ if setting.obsolete ~}}
        [Obsolete(""This option is no longer supported and will be removed in a future version."")]
        {{~ end ~}}
        public {{ provider.name }} Set{{ setting.property_name }}(
            Assembly assembly, string resource,
            string? password, X509KeyStorageFlags flags)
        {
            if (assembly is null)
            {
                throw new ArgumentNullException(nameof(assembly));
            }

            if (string.IsNullOrEmpty(resource))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0062), nameof(resource));
            }

            using var stream = assembly.GetManifestResourceStream(resource) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0064));

            return Set{{ setting.property_name }}(stream, password, flags);
        }

        /// <summary>
        /// Configures {{ setting.description }}.
        /// </summary>
        /// <param name=""stream"">The stream containing the certificate.</param>
        /// <param name=""password"">The password used to open the certificate.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        {{~ if setting.obsolete ~}}
        [Obsolete(""This option is no longer supported and will be removed in a future version."")]
        {{~ end ~}}
        public {{ provider.name }} Set{{ setting.property_name }}(Stream stream, string? password)
#if SUPPORTS_EPHEMERAL_KEY_SETS
            // Note: ephemeral key sets are currently not supported on macOS.
            => Set{{ setting.property_name }}(stream, password, RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ?
                X509KeyStorageFlags.MachineKeySet :
                X509KeyStorageFlags.EphemeralKeySet);
#else
            => Set{{ setting.property_name }}(stream, password, X509KeyStorageFlags.MachineKeySet);
#endif

        /// <summary>
        /// Configures {{ setting.description }}.
        /// </summary>
        /// <param name=""stream"">The stream containing the certificate.</param>
        /// <param name=""password"">The password used to open the certificate.</param>
        /// <param name=""flags"">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        {{~ if setting.obsolete ~}}
        [Obsolete(""This option is no longer supported and will be removed in a future version."")]
        {{~ end ~}}
        public {{ provider.name }} Set{{ setting.property_name }}(Stream stream, string? password, X509KeyStorageFlags flags)
        {
            if (stream is null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);

#if SUPPORTS_CERTIFICATE_LOADER
            var certificate = X509Certificate2.GetCertContentType(buffer.ToArray()) switch
            {
                X509ContentType.Pkcs12 => X509CertificateLoader.LoadPkcs12(buffer.ToArray(), password, flags),

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0454))
            };
#else
            var certificate = new X509Certificate2(buffer.ToArray(), password, flags);
#endif
            return Set{{ setting.property_name }}(certificate);
        }

        /// <summary>
        /// Configures {{ setting.description }}.
        /// </summary>
        /// <param name=""thumbprint"">The thumbprint of the certificate used to identify it in the X.509 store.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        {{~ if setting.obsolete ~}}
        [Obsolete(""This option is no longer supported and will be removed in a future version."")]
        {{~ end ~}}
        public {{ provider.name }} Set{{ setting.property_name }}(string thumbprint)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0065), nameof(thumbprint));
            }

            return Set{{ setting.property_name }}(
                GetCertificate(StoreLocation.CurrentUser, thumbprint) ??
                GetCertificate(StoreLocation.LocalMachine, thumbprint) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0066)));

            static X509Certificate2? GetCertificate(StoreLocation location, string thumbprint)
            {
                using var store = new X509Store(StoreName.My, location);
                store.Open(OpenFlags.ReadOnly);

                return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                    .OfType<X509Certificate2>()
                    .SingleOrDefault();
            }
        }

        /// <summary>
        /// Configures {{ setting.description }}.
        /// </summary>
        /// <param name=""thumbprint"">The thumbprint of the certificate used to identify it in the X.509 store.</param>
        /// <param name=""name"">The name of the X.509 store.</param>
        /// <param name=""location"">The location of the X.509 store.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        {{~ if setting.obsolete ~}}
        [Obsolete(""This option is no longer supported and will be removed in a future version."")]
        {{~ end ~}}
        public {{ provider.name }} Set{{ setting.property_name }}(string thumbprint, StoreName name, StoreLocation location)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0065), nameof(thumbprint));
            }

            using var store = new X509Store(name, location);
            store.Open(OpenFlags.ReadOnly);

            return Set{{ setting.property_name }}(
                store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                    .OfType<X509Certificate2>()
                    .SingleOrDefault() ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0066)));
        }
        {{~ else if setting.clr_type == 'bool' ~}}
        /// <summary>
        /// Configures {{ setting.description }}.
        /// </summary>
        /// <param name=""{{ setting.parameter_name }}"">{{ setting.description | string.capitalize }}.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        {{~ if setting.obsolete ~}}
        [Obsolete(""This option is no longer supported and will be removed in a future version."")]
        {{~ end ~}}
        public {{ provider.name }} Set{{ setting.property_name }}(bool {{ setting.parameter_name }})
            => Set(registration => registration.Get{{ provider.name }}Settings().{{ setting.property_name }} = {{ setting.parameter_name }});
        {{~ else ~}}
        /// <summary>
        /// Configures {{ setting.description }}.
        /// </summary>
        /// <param name=""{{ setting.parameter_name }}"">{{ setting.description | string.capitalize }}.</param>
        /// <returns>The <see cref=""OpenIddictClientWebIntegrationBuilder.{{ provider.name }}""/> instance.</returns>
        {{~ if setting.obsolete ~}}
        [Obsolete(""This option is no longer supported and will be removed in a future version."")]
        {{~ end ~}}
        public {{ provider.name }} Set{{ setting.property_name }}({{ setting.clr_type }} {{ setting.parameter_name }})
        {
            if ({{ setting.parameter_name }} is null)
            {
                throw new ArgumentNullException(nameof({{ setting.parameter_name }}));
            }

            return Set(registration => registration.Get{{ provider.name }}Settings().{{ setting.property_name }} = {{ setting.parameter_name }});
        }
        {{~ end ~}}

        {{~ end ~}}

        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals(object? obj) => base.Equals(obj);

        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode() => base.GetHashCode();

        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override string? ToString() => base.ToString();

        /// <summary>
        /// Amends the client registration created by the {{ provider.display_name }} integration.
        /// </summary>
        /// <param name=""configuration"">The delegate used to configure the {{ provider.display_name }} client registration.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref=""OpenIddictClientRegistration""/> instance.</returns>
        private {{ provider.name }} Set(Action<OpenIddictClientRegistration> configuration)
        {
            if (configuration is null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            configuration(Registration);

            return this;
        }
    }
    {{~ end ~}}
}
");
            return template.Render(new
            {
                Providers = document.Root.Elements("Provider")
                    .Select(provider => new
                    {
                        Name = (string) provider.Attribute("Name"),
                        DisplayName = (string?) provider.Attribute("DisplayName") ?? (string) provider.Attribute("Name"),
                        Documentation = (string?) provider.Attribute("Documentation"),

                        Obsolete = (bool?) provider.Attribute("Obsolete") ?? false,

                        Environments = provider.Elements("Environment").Select(environment => new
                        {
                            Name = (string?) environment.Attribute("Name") ?? "Production"
                        })
                        .ToList(),

                        Settings = provider.Elements("Setting").Select(setting => new
                        {
                            PropertyName = (string) setting.Attribute("PropertyName"),
                            ParameterName = (string) setting.Attribute("ParameterName"),

                            Collection = (bool?) setting.Attribute("Collection") ?? false,
                            Obsolete = (bool?) setting.Attribute("Obsolete") ?? false,

                            Description = (string) setting.Attribute("Description") is string description ?
                                char.ToLower(description[0], CultureInfo.GetCultureInfo("en-US")) + description[1..] : null,
                            ClrType = (string) setting.Attribute("Type") switch
                            {
                                "Boolean" => "bool",
                                "EncryptionKey" => (string?) setting.Element("EncryptionAlgorithm")?.Attribute("Value") switch
                                {
                                    "RS256" or "RS384" or "RS512" => "RsaSecurityKey",

                                    _ => "SecurityKey"
                                },

                                "SigningCertificate" => "X509Certificate2",

                                "SigningKey" => (string?) setting.Element("SigningAlgorithm")?.Attribute("Value") switch
                                {
                                    "ES256" or "ES384" or "ES512" => "ECDsaSecurityKey",
                                    "PS256" or "PS384" or "PS512" or "RS256" or "RS384" or "RS512" => "RsaSecurityKey",

                                    _ => "SecurityKey"
                                },

                                "String" => "string",
                                "StringHashSet" => "HashSet<string>",
                                "Uri" => "Uri",

                                string value => value
                            }
                        })
                        .ToList()
                    })
                    .ToList()
            });
        }

        static string GenerateConstants(XDocument document)
        {
            var template = Template.Parse(@"#nullable enable

namespace OpenIddict.Client.WebIntegration;

public static partial class OpenIddictClientWebIntegrationConstants
{
    {{~ for provider in providers ~}}
    public static class {{ provider.name }}
    {
        public static class Environments
        {
            {{~ for environment in provider.environments ~}}
            public const string {{ environment.name }} = ""{{ environment.name }}"";
            {{~ end ~}}
        }

        public static class Properties
        {
            {{~ for property in provider.properties ~}}
            public const string {{ property.name }} = ""{{ property.dictionary_key }}"";
            {{~ end ~}}
        }
    }
    {{~ end ~}}

    public static class Providers
    {
        {{~ for provider in providers ~}}
        public const string {{ provider.name }} = ""{{ provider.name }}"";
        {{~ end ~}}
    }

    public static class ProviderTypes
    {
        {{~ for provider in providers ~}}
        public const string {{ provider.name }} = ""{{ provider.id }}"";
        {{~ end ~}}
    }
}
");
            return template.Render(new
            {
                Providers = document.Root.Elements("Provider")
                    .Select(provider => new
                    {
                        Name = (string) provider.Attribute("Name"),
                        Id = (string) provider.Attribute("Id"),

                        Environments = provider.Elements("Environment").Select(environment => new
                        {
                            Name = (string?) environment.Attribute("Name") ?? "Production"
                        })
                        .ToList(),

                        Properties = provider.Elements("Property").Select(property => new
                        {
                            Name = (string) property.Attribute("Name"),
                            DictionaryKey = (string) property.Attribute("DictionaryKey")
                        })
                        .ToList(),
                    })
                    .ToList()
            });
        }

        static string GenerateConfigurationClasses(XDocument document)
        {
            var template = Template.Parse(@"#nullable enable
#pragma warning disable CS0618

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Client;
using OpenIddict.Extensions;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;
using static OpenIddict.Extensions.OpenIddictHelpers;

namespace OpenIddict.Client.WebIntegration;

public sealed partial class OpenIddictClientWebIntegrationConfiguration
{
    public static partial void ConfigureProvider(OpenIddictClientRegistration registration)
    {
        {{~ for provider in providers ~}}
        {{~ if for.index == 0 ~}}
        if (registration.ProviderType is ProviderTypes.{{ provider.name }})
        {{~ else ~}}
        else if (registration.ProviderType is ProviderTypes.{{ provider.name }})
        {{~ end ~}}
        {
            if (registration.ProviderSettings is not OpenIddictClientWebIntegrationSettings.{{ provider.name }} settings)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0406));
            }

            {{~ for setting in provider.settings ~}}
            {{~ if setting.default_value ~}}
            {{~ if setting.type == 'String' ~}} 
            if (string.IsNullOrEmpty(settings.{{ setting.property_name }}))
            {
                settings.{{ setting.property_name }} = ""{{ setting.default_value }}"";
            }
            {{~ else if setting.type == 'Uri' ~}} 
            if (settings.{{ setting.property_name }} is null)
            {
                settings.{{ setting.property_name }} = new Uri(""{{ setting.default_value }}"", UriKind.RelativeOrAbsolute);
            }
            {{~ else if setting.type == 'Boolean' ~}}
            if (settings.{{ setting.property_name }} is null)
            {
                settings.{{ setting.property_name }} = {{ setting.default_value }};
            }
            {{~ end ~}}
            {{~ end ~}}

            {{~ if setting.collection ~}}
            if (settings.{{ setting.property_name }}.Count is 0)
            {
                {{~ for item in setting.items ~}}
                {{~ if item.default && !item.required ~}}
                settings.{{ setting.property_name }}.Add(""{{ item.value }}"");
                {{~ end ~}}
                {{~ end ~}}
            }
            {{~ end ~}}

            {{~ for item in setting.items ~}}
            {{~ if item.required ~}}
            settings.{{ setting.property_name }}.Add(""{{ item.value }}"");
            {{~ end ~}}
            {{~ end ~}}
            {{~ end ~}}

            {{~ for environment in provider.environments ~}}
            if (settings.Environment is OpenIddictClientWebIntegrationConstants.{{ provider.name }}.Environments.{{ environment.name }})
            {
                if (registration.Scopes.Count is 0)
                {
                    {{~ for scope in environment.scopes ~}}
                    {{~ if scope.default && !scope.required ~}}
                    registration.Scopes.Add(""{{ scope.name }}"");
                    {{~ end ~}}
                    {{~ end ~}}
                }

                {{~ for scope in environment.scopes ~}}
                {{~ if scope.required ~}}
                registration.Scopes.Add(""{{ scope.name }}"");
                {{~ end ~}}
                {{~ end ~}}
            }
            {{~ end ~}}

            {{~ for setting in provider.settings ~}}
            {{~ if setting.required ~}}
            {{~ if setting.type == 'String' ~}}
            if (string.IsNullOrEmpty(settings.{{ setting.property_name }}))
            {{~ else ~}}
            if (settings.{{ setting.property_name }} is null)
            {{~ end ~}}
            {
                throw new InvalidOperationException(SR.FormatID0332(nameof(settings.{{ setting.property_name }}), Providers.{{ provider.name }}));
            }
            {{~ end ~}}

            {{~ if setting.type == 'Uri' ~}}
            if (!settings.{{ setting.property_name }}.IsAbsoluteUri || OpenIddictHelpers.IsImplicitFileUri(settings.{{ setting.property_name }}))
            {
                throw new InvalidOperationException(SR.FormatID0350(nameof(settings.{{ setting.property_name }}), Providers.{{ provider.name }}));
            }
            {{~ end ~}}
            {{~ end ~}}

            registration.ProviderName ??= Providers.{{ provider.name }};
            registration.ProviderDisplayName ??= ""{{ provider.display_name }}"";

            registration.Issuer ??= settings.Environment switch
            {
                {{~ for environment in provider.environments ~}}
                OpenIddictClientWebIntegrationConstants.{{ provider.name }}.Environments.{{ environment.name }}
                    => new Uri($""{{ environment.issuer | string.replace '\'' '""' }}"", UriKind.Absolute),
                {{~ end ~}}

                _ => throw new InvalidOperationException(SR.FormatID0194(nameof(settings.Environment)))
            };

            registration.ConfigurationEndpoint ??= settings.Environment switch
            {
                {{~ for environment in provider.environments ~}}
                OpenIddictClientWebIntegrationConstants.{{ provider.name }}.Environments.{{ environment.name }}
                {{~ if environment.configuration_endpoint ~}}
                    => new Uri($""{{ environment.configuration_endpoint | string.replace '\'' '""' }}"", UriKind.Absolute),
                {{~ else ~}}
                    => null,
                {{~ end ~}}
                {{~ end ~}}

                _ => throw new InvalidOperationException(SR.FormatID0194(nameof(settings.Environment)))
            };

            registration.Configuration ??= settings.Environment switch
            {
                {{~ for environment in provider.environments ~}}
                {{~ if environment.configuration ~}}
                OpenIddictClientWebIntegrationConstants.{{ provider.name }}.Environments.{{ environment.name }} => new OpenIddictConfiguration
                {
                    {{~ if environment.configuration.authorization_endpoint ~}}
                    AuthorizationEndpoint = new Uri($""{{ environment.configuration.authorization_endpoint | string.replace '\'' '""' }}"", UriKind.Absolute),
                    {{~ end ~}}

                    {{~ if environment.configuration.device_authorization_endpoint ~}}
                    DeviceAuthorizationEndpoint = new Uri($""{{ environment.configuration.device_authorization_endpoint | string.replace '\'' '""' }}"", UriKind.Absolute),
                    {{~ end ~}}

                    {{~ if environment.configuration.introspection_endpoint ~}}
                    IntrospectionEndpoint = new Uri($""{{ environment.configuration.introspection_endpoint | string.replace '\'' '""' }}"", UriKind.Absolute),
                    {{~ end ~}}

                    {{~ if environment.configuration.revocation_endpoint ~}}
                    RevocationEndpoint = new Uri($""{{ environment.configuration.revocation_endpoint | string.replace '\'' '""' }}"", UriKind.Absolute),
                    {{~ end ~}}

                    {{~ if environment.configuration.token_endpoint ~}}
                    TokenEndpoint = new Uri($""{{ environment.configuration.token_endpoint | string.replace '\'' '""' }}"", UriKind.Absolute),
                    {{~ end ~}}

                    {{~ if environment.configuration.user_info_endpoint ~}}
                    UserInfoEndpoint = new Uri($""{{ environment.configuration.user_info_endpoint | string.replace '\'' '""' }}"", UriKind.Absolute),
                    {{~ end ~}}

                    CodeChallengeMethodsSupported =
                    {
                        {{~ for method in environment.configuration.code_challenge_methods_supported ~}}
                        ""{{ method }}"",
                        {{~ end ~}}
                    },

                    GrantTypesSupported =
                    {
                        {{~ for type in environment.configuration.grant_types_supported ~}}
                        ""{{ type }}"",
                        {{~ end ~}}
                    },

                    ResponseModesSupported =
                    {
                        {{~ for mode in environment.configuration.response_modes_supported ~}}
                        ""{{ mode }}"",
                        {{~ end ~}}
                    },

                    ResponseTypesSupported =
                    {
                        {{~ for type in environment.configuration.response_types_supported ~}}
                        ""{{ type }}"",
                        {{~ end ~}}
                    },

                    ScopesSupported =
                    {
                        {{~ for scope in environment.configuration.scopes_supported ~}}
                        ""{{ scope }}"",
                        {{~ end ~}}
                    },

                    DeviceAuthorizationEndpointAuthMethodsSupported =
                    {
                        {{~ for method in environment.configuration.device_authorization_endpoint_auth_methods_supported ~}}
                        ""{{ method }}"",
                        {{~ end ~}}
                    },

                    IntrospectionEndpointAuthMethodsSupported =
                    {
                        {{~ for method in environment.configuration.introspection_endpoint_auth_methods_supported ~}}
                        ""{{ method }}"",
                        {{~ end ~}}
                    },

                    RevocationEndpointAuthMethodsSupported =
                    {
                        {{~ for method in environment.configuration.revocation_endpoint_auth_methods_supported ~}}
                        ""{{ method }}"",
                        {{~ end ~}}
                    },

                    TokenEndpointAuthMethodsSupported =
                    {
                        {{~ for method in environment.configuration.token_endpoint_auth_methods_supported ~}}
                        ""{{ method }}"",
                        {{~ end ~}}
                    }
                },
                {{~ else ~}}
                OpenIddictClientWebIntegrationConstants.{{ provider.name }}.Environments.{{ environment.name }} => null,
                {{~ end ~}}
                {{~ end ~}}

                _ => throw new InvalidOperationException(SR.FormatID0194(nameof(settings.Environment)))
            };

            {{~ for setting in provider.settings ~}}
            {{~ if setting.type == 'EncryptionKey' ~}}
            if (settings.{{ setting.property_name }} is not null)
            {
                registration.EncryptionCredentials.Add(new EncryptingCredentials(settings.{{ setting.property_name }}, ""{{ setting.encryption_algorithm }}"", SecurityAlgorithms.Aes256CbcHmacSha512));
            }
            {{~ end ~}}
            {{~ end ~}}

            {{~ for setting in provider.settings ~}}
            {{~ if setting.type == 'SigningCertificate' ~}}
            if (settings.{{ setting.property_name }} is not null)
            {
                var key = new X509SecurityKey(settings.{{ setting.property_name }});
                if (key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256))
                {
                    registration.SigningCredentials.Add(new SigningCredentials(key, SecurityAlgorithms.RsaSha256));
                }

                else if (key.IsSupportedAlgorithm(SecurityAlgorithms.HmacSha256))
                {
                    registration.SigningCredentials.Add(new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
                }

#if SUPPORTS_ECDSA
                // Note: ECDSA algorithms are bound to specific curves and must be treated separately.
                else if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256))
                {
                    registration.SigningCredentials.Add(new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256));
                }

                else if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384))
                {
                    registration.SigningCredentials.Add(new SigningCredentials(key, SecurityAlgorithms.EcdsaSha384));
                }

                else if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512))
                {
                    registration.SigningCredentials.Add(new SigningCredentials(key, SecurityAlgorithms.EcdsaSha512));
                }
#else
                else if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256) ||
                         key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384) ||
                         key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512))
                {
                    throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0069));
                }
#endif
                else
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0068));
                }
            }
            {{~ end ~}}
            {{~ if setting.type == 'SigningKey' ~}}
            if (settings.{{ setting.property_name }} is not null)
            {
                // If the signing key is an asymmetric security key, ensure it has a private key.
                if (settings.{{ setting.property_name }} is AsymmetricSecurityKey asymmetricSecurityKey &&
                    asymmetricSecurityKey.PrivateKeyStatus is PrivateKeyStatus.DoesNotExist)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0067));
                }

                {{~ if setting.signing_algorithm ~}}
                registration.SigningCredentials.Add(new SigningCredentials(settings.{{ setting.property_name }}, ""{{ setting.signing_algorithm }}""));
                {{~ else ~}}
                if (settings.{{ setting.property_name }}.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256))
                {
                    registration.SigningCredentials.Add(new SigningCredentials(settings.{{ setting.property_name }}, SecurityAlgorithms.RsaSha256));
                }

                else if (settings.{{ setting.property_name }}.IsSupportedAlgorithm(SecurityAlgorithms.HmacSha256))
                {
                    registration.SigningCredentials.Add(new SigningCredentials(settings.{{ setting.property_name }}, SecurityAlgorithms.HmacSha256));
                }

#if SUPPORTS_ECDSA
                // Note: ECDSA algorithms are bound to specific curves and must be treated separately.
                else if (settings.{{ setting.property_name }}.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256))
                {
                    registration.SigningCredentials.Add(new SigningCredentials(settings.{{ setting.property_name }}, SecurityAlgorithms.EcdsaSha256));
                }

                else if (settings.{{ setting.property_name }}.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384))
                {
                    registration.SigningCredentials.Add(new SigningCredentials(settings.{{ setting.property_name }}, SecurityAlgorithms.EcdsaSha384));
                }

                else if (settings.{{ setting.property_name }}.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512))
                {
                    registration.SigningCredentials.Add(new SigningCredentials(settings.{{ setting.property_name }}, SecurityAlgorithms.EcdsaSha512));
                }
#else
                else if (settings.{{ setting.property_name }}.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256) ||
                         settings.{{ setting.property_name }}.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384) ||
                         settings.{{ setting.property_name }}.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512))
                {
                    throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0069));
                }
#endif
                else
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0068));
                }
                {{~ end ~}}
            }
            {{~ end ~}}
            {{~ end ~}}
        }
        {{~ end ~}}

        else
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0407));
        }
    }
}
");
            return template.Render(new
            {
                Providers = document.Root.Elements("Provider")
                    .Select(provider => new
                    {
                        Name = (string) provider.Attribute("Name"),
                        DisplayName = (string?) provider.Attribute("DisplayName") ?? (string) provider.Attribute("Name"),

                        Environments = provider.Elements("Environment").Select(environment => new
                        {
                            Name = (string?) environment.Attribute("Name") ?? "Production",

                            Issuer = (string) environment.Attribute("Issuer"),
                            ConfigurationEndpoint = (string?) environment.Attribute("ConfigurationEndpoint"),

                            Configuration = environment.Element("Configuration") switch
                            {
                                XElement configuration => new
                                {
                                    AuthorizationEndpoint = (string?) configuration.Attribute("AuthorizationEndpoint"),
                                    DeviceAuthorizationEndpoint = (string?) configuration.Attribute("DeviceAuthorizationEndpoint"),
                                    IntrospectionEndpoint = (string?) configuration.Attribute("IntrospectionEndpoint"),
                                    RevocationEndpoint = (string?) configuration.Attribute("RevocationEndpoint"),
                                    TokenEndpoint = (string?) configuration.Attribute("TokenEndpoint"),
                                    UserInfoEndpoint = (string?) configuration.Attribute("UserInfoEndpoint"),

                                    CodeChallengeMethodsSupported = configuration.Elements("CodeChallengeMethod").ToList() switch
                                    {
                                        { Count: > 0 } methods => methods.Select(type => (string?) type.Attribute("Value")).ToList(),

                                        _ => []
                                    },

                                    GrantTypesSupported = configuration.Elements("GrantType").ToList() switch
                                    {
                                        { Count: > 0 } types => types.Select(type => (string?) type.Attribute("Value")).ToList(),

                                        // If no explicit grant type was set, assume the provider only supports the code flow.
                                        _ => [GrantTypes.AuthorizationCode]
                                    },

                                    ResponseModesSupported = configuration.Elements("ResponseMode").ToList() switch
                                    {
                                        { Count: > 0 } modes => modes.Select(type => (string?) type.Attribute("Value")).ToList(),

                                        // If no explicit response mode was set, assume the provider only supports the query response mode.
                                        _ => [ResponseModes.Query]
                                    },

                                    ResponseTypesSupported = configuration.Elements("ResponseType").ToList() switch
                                    {
                                        { Count: > 0 } types => types.Select(type => (string?) type.Attribute("Value")).ToList(),

                                        // If no explicit response type was set, assume the provider only supports the code flow.
                                        _ => [ResponseTypes.Code]
                                    },

                                    ScopesSupported = configuration.Elements("Scope").ToList() switch
                                    {
                                        { Count: > 0 } types => types.Select(type => (string?) type.Attribute("Value")).ToList(),

                                        _ => []
                                    },

                                    DeviceAuthorizationEndpointAuthMethodsSupported = configuration.Elements("DeviceAuthorizationEndpointAuthMethod").ToList() switch
                                    {
                                        { Count: > 0 } methods => methods.Select(type => (string?) type.Attribute("Value")).ToList(),

                                        // If no explicit client authentication method was set, assume the provider only supports
                                        // flowing the client credentials as part of the device authorization request payload.
                                        _ => [ClientAuthenticationMethods.ClientSecretPost]
                                    },

                                    IntrospectionEndpointAuthMethodsSupported = configuration.Elements("IntrospectionEndpointAuthMethod").ToList() switch
                                    {
                                        { Count: > 0 } methods => methods.Select(type => (string?) type.Attribute("Value")).ToList(),

                                        // If no explicit client authentication method was set, assume the provider only
                                        // supports flowing the client credentials as part of the introspection request payload.
                                        _ => [ClientAuthenticationMethods.ClientSecretPost]
                                    },

                                    RevocationEndpointAuthMethodsSupported = configuration.Elements("RevocationEndpointAuthMethod").ToList() switch
                                    {
                                        { Count: > 0 } methods => methods.Select(type => (string?) type.Attribute("Value")).ToList(),

                                        // If no explicit client authentication method was set, assume the provider only
                                        // supports flowing the client credentials as part of the revocation request payload.
                                        _ => [ClientAuthenticationMethods.ClientSecretPost]
                                    },

                                    TokenEndpointAuthMethodsSupported = configuration.Elements("TokenEndpointAuthMethod").ToList() switch
                                    {
                                        { Count: > 0 } methods => methods.Select(type => (string?) type.Attribute("Value")).ToList(),

                                        // If no explicit client authentication method was set, assume the provider only
                                        // supports flowing the client credentials as part of the token request payload.
                                        _ => [ClientAuthenticationMethods.ClientSecretPost]
                                    }
                                },

                                _ => null
                            },

                            Scopes = environment.Elements("Scope").Select(setting => new
                            {
                                Name = (string) setting.Attribute("Name"),
                                Default = (bool?) setting.Attribute("Default") ?? false,
                                Required = (bool?) setting.Attribute("Required") ?? false
                            })
                        })
                        .ToList(),

                        Settings = provider.Elements("Setting").Select(setting => new
                        {
                            PropertyName = (string) setting.Attribute("PropertyName"),

                            Type = (string) setting.Attribute("Type"),
                            Required = (bool?) setting.Attribute("Required") ?? false,
                            Collection = (bool?) setting.Attribute("Collection") ?? false,

                            EncryptionAlgorithm = (string?) setting.Element("EncryptionAlgorithm")?.Attribute("Value"),
                            SigningAlgorithm = (string?) setting.Element("SigningAlgorithm")?.Attribute("Value"),

                            DefaultValue = (string?) setting.Attribute("DefaultValue"),

                            Items = setting.Elements("Item").Select(item => new
                            {
                                Value = (string) item.Attribute("Value"),
                                Default = (bool?) item.Attribute("Default") ?? false,
                                Required = (bool?) item.Attribute("Required") ?? false
                            })
                            .ToList()
                        })
                        .ToList()
                    })
                    .ToList()
            });
        }

        static string GenerateHelpers(XDocument document)
        {
            var template = Template.Parse(@"#nullable enable

using Microsoft.IdentityModel.Tokens;
using OpenIddict.Client;
using OpenIddict.Client.WebIntegration;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

public static partial class OpenIddictClientWebIntegrationHelpers
{
    {{~ for provider in providers ~}}
    /// <summary>
    /// Resolves the {{ provider.display_name }} provider settings from the specified registration.
    /// </summary>
    /// <param name=""registration"">The client registration.</param>
    /// <returns>The {{ provider.display_name }} provider settings.</returns>
    /// <exception cref=""InvalidOperationException"">The provider options cannot be resolved.</exception>
    public static OpenIddictClientWebIntegrationSettings.{{ provider.name }} Get{{ provider.name }}Settings(this OpenIddictClientRegistration registration)
        => registration.ProviderSettings is OpenIddictClientWebIntegrationSettings.{{ provider.name }} settings ? settings :
            throw new InvalidOperationException(SR.FormatID0333(Providers.{{ provider.name }}));

    {{~ end ~}}
}
");
            return template.Render(new
            {
                Providers = document.Root.Elements("Provider")
                    .Select(provider => new
                    {
                        Name = (string) provider.Attribute("Name"),
                        DisplayName = (string?) provider.Attribute("DisplayName") ?? (string) provider.Attribute("Name")
                    })
                    .ToList()
            });
        }

        static string GenerateSettings(XDocument document)
        {
            var template = Template.Parse(@"#nullable enable

using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Client.WebIntegration;

public sealed partial class OpenIddictClientWebIntegrationSettings
{
    {{~ for provider in providers ~}}
    /// <summary>
    /// Provides various options needed to configure the {{ provider.display_name }} integration.
    /// </summary>
    public sealed class {{ provider.name }}
    {
        /// <summary>
        /// Gets or sets the environment that determines the endpoints to use (by default, ""Production"").
        /// </summary>
        public string? Environment { get; set; } = OpenIddictClientWebIntegrationConstants.{{ provider.name }}.Environments.Production;

        {{~ for setting in provider.settings ~}}
        /// <summary>
        /// Gets or sets {{ setting.description }}.
        /// </summary>
        {{~ if setting.obsolete ~}}
        [Obsolete(""This option is no longer supported and will be removed in a future version."")]
        {{~ end ~}}
        {{~ if setting.collection ~}}
        public HashSet<{{ setting.clr_type }}> {{ setting.property_name }} { get; } = new();
        {{~ else ~}}
        public {{ setting.clr_type }}? {{ setting.property_name }} { get; set; }
        {{~ end ~}}

        {{~ end ~}}
    }
    {{~ end ~}}
}
");
            return template.Render(new
            {
                Providers = document.Root.Elements("Provider")
                    .Select(provider => new
                    {
                        Name = (string) provider.Attribute("Name"),
                        DisplayName = (string?) provider.Attribute("DisplayName") ?? (string) provider.Attribute("Name"),

                        Settings = provider.Elements("Setting").Select(setting => new
                        {
                            PropertyName = (string) setting.Attribute("PropertyName"),

                            Collection = (bool?) setting.Attribute("Collection") ?? false,
                            Obsolete = (bool?) setting.Attribute("Obsolete") ?? false,

                            Description = (string) setting.Attribute("Description") is string description ?
                                char.ToLower(description[0], CultureInfo.GetCultureInfo("en-US")) + description[1..] : null,
                            ClrType = (string) setting.Attribute("Type") switch
                            {
                                "Boolean" => "bool",
                                "EncryptionKey" => (string?) setting.Element("EncryptionAlgorithm")?.Attribute("Value") switch
                                {
                                    "RS256" or "RS384" or "RS512" => "RsaSecurityKey",

                                    _ => "SecurityKey"
                                },

                                "SigningCertificate" => "X509Certificate2",

                                "SigningKey" => (string?) setting.Element("SigningAlgorithm")?.Attribute("Value") switch
                                {
                                    "ES256" or "ES384" or "ES512" => "ECDsaSecurityKey",
                                    "PS256" or "PS384" or "PS512" or "RS256" or "RS384" or "RS512" => "RsaSecurityKey",

                                    _ => "SecurityKey"
                                },

                                "String" => "string",
                                "StringHashSet" => "HashSet<string>",
                                "Uri" => "Uri",

                                string value => value
                            }
                        })
                        .ToList()
                    })
                    .ToList()
            });
        }
    }

    public void Initialize(GeneratorInitializationContext context)
    {
    }
}

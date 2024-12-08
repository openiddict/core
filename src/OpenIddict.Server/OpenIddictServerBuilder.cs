/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Extensions;
using OpenIddict.Server;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict server services.
/// </summary>
public sealed class OpenIddictServerBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictServerBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictServerBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Registers an event handler using the specified configuration delegate.
    /// </summary>
    /// <typeparam name="TContext">The event context type.</typeparam>
    /// <param name="configuration">The configuration delegate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerBuilder AddEventHandler<TContext>(
        Action<OpenIddictServerHandlerDescriptor.Builder<TContext>> configuration)
        where TContext : OpenIddictServerEvents.BaseContext
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        // Note: handlers registered using this API are assumed to be custom handlers by default.
        var builder = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
            .SetType(OpenIddictServerHandlerType.Custom);

        configuration(builder);

        return AddEventHandler(builder.Build());
    }

    /// <summary>
    /// Registers an event handler using the specified descriptor.
    /// </summary>
    /// <param name="descriptor">The handler descriptor.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerBuilder AddEventHandler(OpenIddictServerHandlerDescriptor descriptor)
    {
        if (descriptor is null)
        {
            throw new ArgumentNullException(nameof(descriptor));
        }

        // Register the handler in the services collection.
        Services.Add(descriptor.ServiceDescriptor);

        return Configure(options => options.Handlers.Add(descriptor));
    }

    /// <summary>
    /// Removes the event handler that matches the specified descriptor.
    /// </summary>
    /// <param name="descriptor">The descriptor corresponding to the handler to remove.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerBuilder RemoveEventHandler(OpenIddictServerHandlerDescriptor descriptor)
    {
        if (descriptor is null)
        {
            throw new ArgumentNullException(nameof(descriptor));
        }

        Services.RemoveAll(descriptor.ServiceDescriptor.ServiceType);

        Services.PostConfigure<OpenIddictServerOptions>(options =>
        {
            for (var index = options.Handlers.Count - 1; index >= 0; index--)
            {
                if (options.Handlers[index].ServiceDescriptor.ServiceType == descriptor.ServiceDescriptor.ServiceType)
                {
                    options.Handlers.RemoveAt(index);
                }
            }
        });

        return this;
    }

    /// <summary>
    /// Amends the default OpenIddict server configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder Configure(Action<OpenIddictServerOptions> configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Makes client identification optional so that token, introspection and revocation
    /// requests that don't specify a client_id are not automatically rejected.
    /// Enabling this option is NOT recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AcceptAnonymousClients()
        => Configure(options => options.AcceptAnonymousClients = true);

    /// <summary>
    /// Registers encryption credentials.
    /// </summary>
    /// <param name="credentials">The encrypting credentials.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionCredentials(EncryptingCredentials credentials)
    {
        if (credentials is null)
        {
            throw new ArgumentNullException(nameof(credentials));
        }

        return Configure(options => options.EncryptionCredentials.Add(credentials));
    }

    /// <summary>
    /// Registers an encryption key.
    /// </summary>
    /// <param name="key">The security key.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionKey(SecurityKey key)
    {
        if (key is null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        // If the encryption key is an asymmetric security key, ensure it has a private key.
        if (key is AsymmetricSecurityKey asymmetricSecurityKey &&
            asymmetricSecurityKey.PrivateKeyStatus is PrivateKeyStatus.DoesNotExist)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0055));
        }

        if (key.IsSupportedAlgorithm(SecurityAlgorithms.Aes256KW))
        {
            if (key.KeySize != 256)
            {
                throw new InvalidOperationException(SR.FormatID0283(256, key.KeySize));
            }

            return AddEncryptionCredentials(new EncryptingCredentials(key,
                SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes256CbcHmacSha512));
        }

        if (key.IsSupportedAlgorithm(SecurityAlgorithms.RsaOAEP))
        {
            return AddEncryptionCredentials(new EncryptingCredentials(key,
                SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512));
        }

        throw new InvalidOperationException(SR.GetResourceString(SR.ID0056));
    }
    
    /// <summary>
    /// Registers multiple encryption keys.
    /// </summary>
    /// <param name="keys">The security keys.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionKeys(IEnumerable<SecurityKey> keys)
    {
        if (keys is null)
        {
            throw new ArgumentNullException(nameof(keys));
        }

        return keys.Aggregate(this, static (builder, key) => builder.AddEncryptionKey(key));
    }

    /// <summary>
    /// Registers (and generates if necessary) a user-specific development encryption certificate.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddDevelopmentEncryptionCertificate()
        => AddDevelopmentEncryptionCertificate(new X500DistinguishedName("CN=OpenIddict Server Encryption Certificate"));

    /// <summary>
    /// Registers (and generates if necessary) a user-specific development encryption certificate.
    /// </summary>
    /// <param name="subject">The subject name associated with the certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddDevelopmentEncryptionCertificate(X500DistinguishedName subject)
    {
        if (subject is null)
        {
            throw new ArgumentNullException(nameof(subject));
        }

        Services.AddOptions<OpenIddictServerOptions>().Configure<IServiceProvider>((options, provider) =>
        {
#if SUPPORTS_TIME_PROVIDER
            var now = (options.TimeProvider ?? provider.GetService<TimeProvider>())?.GetUtcNow() ?? DateTimeOffset.UtcNow;
#else
            var now = DateTimeOffset.UtcNow;
#endif
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);

            // Try to retrieve the existing development certificates from the specified store.
            // If no valid existing certificate was found, create a new encryption certificate.
            var certificates = store.Certificates
                .Find(X509FindType.FindBySubjectDistinguishedName, subject.Name, validOnly: false)
                .OfType<X509Certificate2>()
                .ToList();

            if (!certificates.Exists(certificate => certificate.NotBefore < now.LocalDateTime && certificate.NotAfter > now.LocalDateTime))
            {
#if SUPPORTS_CERTIFICATE_GENERATION
                using var algorithm = OpenIddictHelpers.CreateRsaKey(size: 2048);

                var request = new CertificateRequest(subject, algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, critical: true));

                var certificate = request.CreateSelfSigned(now, now.AddYears(2));

                // Note: setting the friendly name is not supported on Unix machines (including Linux and macOS).
                // To ensure an exception is not thrown by the property setter, an OS runtime check is used here.
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    certificate.FriendlyName = "OpenIddict Server Development Encryption Certificate";
                }

                // Note: CertificateRequest.CreateSelfSigned() doesn't mark the key set associated with the certificate
                // as "persisted", which eventually prevents X509Store.Add() from correctly storing the private key.
                // To work around this issue, the certificate payload is manually exported and imported back
                // into a new X509Certificate2 instance specifying the X509KeyStorageFlags.PersistKeySet flag.
                var data = certificate.Export(X509ContentType.Pfx, string.Empty);

                try
                {
                    var flags = X509KeyStorageFlags.PersistKeySet;

                    // Note: macOS requires marking the certificate private key as exportable.
                    // If this flag is not set, a CryptographicException is thrown at runtime.
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                    {
                        flags |= X509KeyStorageFlags.Exportable;
                    }

#if SUPPORTS_CERTIFICATE_LOADER
                    certificate = X509CertificateLoader.LoadPkcs12(data, string.Empty, flags);
#else
                    certificate = new X509Certificate2(data, string.Empty, flags);
#endif
                    certificates.Insert(0, certificate);
                }

                finally
                {
                    Array.Clear(data, 0, data.Length);
                }

                store.Add(certificate);
#else
                throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0264));
#endif
            }

            options.EncryptionCredentials.AddRange(
                from certificate in certificates
                let key = new X509SecurityKey(certificate)
                select new EncryptingCredentials(key, SecurityAlgorithms.RsaOAEP,
                    SecurityAlgorithms.Aes256CbcHmacSha512));
        });

        return this;
    }

    /// <summary>
    /// Registers a new ephemeral encryption key. Ephemeral encryption keys are automatically
    /// discarded when the application shuts down and payloads encrypted using this key are
    /// automatically invalidated. This method should only be used during development.
    /// On production, using a X.509 certificate stored in the machine store is recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEphemeralEncryptionKey()
        => AddEphemeralEncryptionKey(SecurityAlgorithms.RsaOAEP);

    /// <summary>
    /// Registers a new ephemeral encryption key. Ephemeral encryption keys are automatically
    /// discarded when the application shuts down and payloads encrypted using this key are
    /// automatically invalidated. This method should only be used during development.
    /// On production, using a X.509 certificate stored in the machine store is recommended.
    /// </summary>
    /// <param name="algorithm">The algorithm associated with the encryption key.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEphemeralEncryptionKey(string algorithm)
    {
        if (string.IsNullOrEmpty(algorithm))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0057), nameof(algorithm));
        }

        return algorithm switch
        {
            SecurityAlgorithms.Aes256KW
                => AddEncryptionCredentials(new EncryptingCredentials(
                    new SymmetricSecurityKey(OpenIddictHelpers.CreateRandomArray(size: 256)),
                    algorithm, SecurityAlgorithms.Aes256CbcHmacSha512)),

            SecurityAlgorithms.RsaOAEP or
            SecurityAlgorithms.RsaOaepKeyWrap
                => AddEncryptionCredentials(new EncryptingCredentials(
                    new RsaSecurityKey(OpenIddictHelpers.CreateRsaKey(size: 2048)),
                    algorithm, SecurityAlgorithms.Aes256CbcHmacSha512)),

            _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0058))
        };
    }

    /// <summary>
    /// Registers an encryption certificate.
    /// </summary>
    /// <param name="certificate">The encryption certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionCertificate(X509Certificate2 certificate)
    {
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        // If the certificate is a X.509v3 certificate that specifies at least one
        // key usage, ensure that the certificate key can be used for key encryption.
        if (certificate.Version >= 3)
        {
            var extensions = certificate.Extensions.OfType<X509KeyUsageExtension>().ToList();
            if (extensions.Count is not 0 && !extensions.Exists(static extension =>
                extension.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment)))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0060));
            }
        }

        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0061));
        }

        return AddEncryptionKey(new X509SecurityKey(certificate));
    }

    /// <summary>
    /// Registers an encryption certificate retrieved from an embedded resource.
    /// </summary>
    /// <param name="assembly">The assembly containing the certificate.</param>
    /// <param name="resource">The name of the embedded resource.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionCertificate(Assembly assembly, string resource, string? password)
#if SUPPORTS_EPHEMERAL_KEY_SETS
        // Note: ephemeral key sets are currently not supported on macOS.
        => AddEncryptionCertificate(assembly, resource, password, RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ?
            X509KeyStorageFlags.MachineKeySet :
            X509KeyStorageFlags.EphemeralKeySet);
#else
        => AddEncryptionCertificate(assembly, resource, password, X509KeyStorageFlags.MachineKeySet);
#endif

    /// <summary>
    /// Registers an encryption certificate retrieved from an embedded resource.
    /// </summary>
    /// <param name="assembly">The assembly containing the certificate.</param>
    /// <param name="resource">The name of the embedded resource.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <param name="flags">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionCertificate(
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

        return AddEncryptionCertificate(stream, password, flags);
    }

    /// <summary>
    /// Registers an encryption certificate extracted from a stream.
    /// </summary>
    /// <param name="stream">The stream containing the certificate.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionCertificate(Stream stream, string? password)
#if SUPPORTS_EPHEMERAL_KEY_SETS
        // Note: ephemeral key sets are currently not supported on macOS.
        => AddEncryptionCertificate(stream, password, RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ?
            X509KeyStorageFlags.MachineKeySet :
            X509KeyStorageFlags.EphemeralKeySet);
#else
        => AddEncryptionCertificate(stream, password, X509KeyStorageFlags.MachineKeySet);
#endif

    /// <summary>
    /// Registers an encryption certificate extracted from a stream.
    /// </summary>
    /// <param name="stream">The stream containing the certificate.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <param name="flags">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionCertificate(Stream stream, string? password, X509KeyStorageFlags flags)
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
        return AddEncryptionCertificate(certificate);
    }

    /// <summary>
    /// Registers an encryption certificate retrieved from the X.509 user or machine store.
    /// </summary>
    /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionCertificate(string thumbprint)
    {
        if (string.IsNullOrEmpty(thumbprint))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0065), nameof(thumbprint));
        }

        return AddEncryptionCertificate(
            GetCertificate(StoreLocation.CurrentUser, thumbprint)  ??
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
    /// Registers an encryption certificate retrieved from the specified X.509 store.
    /// </summary>
    /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
    /// <param name="name">The name of the X.509 store.</param>
    /// <param name="location">The location of the X.509 store.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionCertificate(string thumbprint, StoreName name, StoreLocation location)
    {
        if (string.IsNullOrEmpty(thumbprint))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0065), nameof(thumbprint));
        }

        using var store = new X509Store(name, location);
        store.Open(OpenFlags.ReadOnly);

        return AddEncryptionCertificate(
            store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                .OfType<X509Certificate2>()
                .SingleOrDefault() ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0066)));
    }
    
    /// <summary>
    /// Registers multiple encryption certificates.
    /// </summary>
    /// <param name="certificates">The encryption certificates.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionCertificates(IEnumerable<X509Certificate2> certificates)
    {
        if (certificates is null)
        {
            throw new ArgumentNullException(nameof(certificates));
        }
        
        return certificates.Aggregate(this, static (builder, certificate) => builder.AddEncryptionCertificate(certificate));
    }

    /// <summary>
    /// Registers signing credentials.
    /// </summary>
    /// <param name="credentials">The signing credentials.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningCredentials(SigningCredentials credentials)
    {
        if (credentials is null)
        {
            throw new ArgumentNullException(nameof(credentials));
        }

        return Configure(options => options.SigningCredentials.Add(credentials));
    }

    /// <summary>
    /// Registers a signing key.
    /// </summary>
    /// <param name="key">The security key.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningKey(SecurityKey key)
    {
        if (key is null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        // If the signing key is an asymmetric security key, ensure it has a private key.
        if (key is AsymmetricSecurityKey asymmetricSecurityKey &&
            asymmetricSecurityKey.PrivateKeyStatus is PrivateKeyStatus.DoesNotExist)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0067));
        }

        if (key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256))
        {
            return AddSigningCredentials(new SigningCredentials(key, SecurityAlgorithms.RsaSha256));
        }

        if (key.IsSupportedAlgorithm(SecurityAlgorithms.HmacSha256))
        {
            return AddSigningCredentials(new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
        }

#if SUPPORTS_ECDSA
        // Note: ECDSA algorithms are bound to specific curves and must be treated separately.
        if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256))
        {
            return AddSigningCredentials(new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256));
        }

        if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384))
        {
            return AddSigningCredentials(new SigningCredentials(key, SecurityAlgorithms.EcdsaSha384));
        }

        if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512))
        {
            return AddSigningCredentials(new SigningCredentials(key, SecurityAlgorithms.EcdsaSha512));
        }
#else
        if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256) ||
            key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384) ||
            key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512))
        {
            throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0069));
        }
#endif

        throw new InvalidOperationException(SR.GetResourceString(SR.ID0068));
    }
    
    /// <summary>
    /// Registers multiple signing keys.
    /// </summary>
    /// <param name="keys">The signing keys.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningKeys(IEnumerable<SecurityKey> keys)
    {
        if (keys is null)
        {
            throw new ArgumentNullException(nameof(keys));
        }

        return keys.Aggregate(this, static (builder, key) => builder.AddSigningKey(key));
    }

    /// <summary>
    /// Registers (and generates if necessary) a user-specific development signing certificate.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddDevelopmentSigningCertificate()
        => AddDevelopmentSigningCertificate(new X500DistinguishedName("CN=OpenIddict Server Signing Certificate"));

    /// <summary>
    /// Registers (and generates if necessary) a user-specific development signing certificate.
    /// </summary>
    /// <param name="subject">The subject name associated with the certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddDevelopmentSigningCertificate(X500DistinguishedName subject)
    {
        if (subject is null)
        {
            throw new ArgumentNullException(nameof(subject));
        }

        Services.AddOptions<OpenIddictServerOptions>().Configure<IServiceProvider>((options, provider) =>
        {
#if SUPPORTS_TIME_PROVIDER
            var now = (options.TimeProvider ?? provider.GetService<TimeProvider>())?.GetUtcNow() ?? DateTimeOffset.UtcNow;
#else
            var now = DateTimeOffset.UtcNow;
#endif
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);

            // Try to retrieve the existing development certificates from the specified store.
            // If no valid existing certificate was found, create a new signing certificate.
            var certificates = store.Certificates
                .Find(X509FindType.FindBySubjectDistinguishedName, subject.Name, validOnly: false)
                .OfType<X509Certificate2>()
                .ToList();

            if (!certificates.Exists(certificate =>
                    certificate.NotBefore < now.LocalDateTime && certificate.NotAfter > now.LocalDateTime))
            {
#if SUPPORTS_CERTIFICATE_GENERATION
                using var algorithm = OpenIddictHelpers.CreateRsaKey(size: 2048);

                var request = new CertificateRequest(subject, algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

                var certificate = request.CreateSelfSigned(now, now.AddYears(2));

                // Note: setting the friendly name is not supported on Unix machines (including Linux and macOS).
                // To ensure an exception is not thrown by the property setter, an OS runtime check is used here.
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    certificate.FriendlyName = "OpenIddict Server Development Signing Certificate";
                }

                // Note: CertificateRequest.CreateSelfSigned() doesn't mark the key set associated with the certificate
                // as "persisted", which eventually prevents X509Store.Add() from correctly storing the private key.
                // To work around this issue, the certificate payload is manually exported and imported back
                // into a new X509Certificate2 instance specifying the X509KeyStorageFlags.PersistKeySet flag.
                var data = certificate.Export(X509ContentType.Pfx, string.Empty);

                try
                {
                    var flags = X509KeyStorageFlags.PersistKeySet;

                    // Note: macOS requires marking the certificate private key as exportable.
                    // If this flag is not set, a CryptographicException is thrown at runtime.
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                    {
                        flags |= X509KeyStorageFlags.Exportable;
                    }

#if SUPPORTS_CERTIFICATE_LOADER
                    certificate = X509CertificateLoader.LoadPkcs12(data, string.Empty, flags);
#else
                    certificate = new X509Certificate2(data, string.Empty, flags);
#endif
                    certificates.Insert(0, certificate);
                }

                finally
                {
                    Array.Clear(data, 0, data.Length);
                }

                store.Add(certificate);
#else
                throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0264));
#endif
            }

            options.SigningCredentials.AddRange(
                from certificate in certificates
                let key = new X509SecurityKey(certificate)
                select new SigningCredentials(key, SecurityAlgorithms.RsaSha256));
        });

        return this;
    }

    /// <summary>
    /// Registers a new ephemeral signing key. Ephemeral signing keys are automatically
    /// discarded when the application shuts down and payloads signed using this key are
    /// automatically invalidated. This method should only be used during development.
    /// On production, using a X.509 certificate stored in the machine store is recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEphemeralSigningKey()
        => AddEphemeralSigningKey(SecurityAlgorithms.RsaSha256);

    /// <summary>
    /// Registers a new ephemeral signing key. Ephemeral signing keys are automatically
    /// discarded when the application shuts down and payloads signed using this key are
    /// automatically invalidated. This method should only be used during development.
    /// On production, using a X.509 certificate stored in the machine store is recommended.
    /// </summary>
    /// <param name="algorithm">The algorithm associated with the signing key.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEphemeralSigningKey(string algorithm)
    {
        if (string.IsNullOrEmpty(algorithm))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0057), nameof(algorithm));
        }

        return algorithm switch
        {
            SecurityAlgorithms.RsaSha256 or
            SecurityAlgorithms.RsaSha384 or
            SecurityAlgorithms.RsaSha512 or
            SecurityAlgorithms.RsaSha256Signature or
            SecurityAlgorithms.RsaSha384Signature or
            SecurityAlgorithms.RsaSha512Signature or
            SecurityAlgorithms.RsaSsaPssSha256 or
            SecurityAlgorithms.RsaSsaPssSha384 or
            SecurityAlgorithms.RsaSsaPssSha512 or
            SecurityAlgorithms.RsaSsaPssSha256Signature or
            SecurityAlgorithms.RsaSsaPssSha384Signature or
            SecurityAlgorithms.RsaSsaPssSha512Signature
                => AddSigningCredentials(new SigningCredentials(new RsaSecurityKey(
                    OpenIddictHelpers.CreateRsaKey(size: 2048)), algorithm)),

#if SUPPORTS_ECDSA
            SecurityAlgorithms.EcdsaSha256 or
            SecurityAlgorithms.EcdsaSha256Signature
                => AddSigningCredentials(new SigningCredentials(new ECDsaSecurityKey(
                    OpenIddictHelpers.CreateEcdsaKey(ECCurve.NamedCurves.nistP256)), algorithm)),

            SecurityAlgorithms.EcdsaSha384 or
            SecurityAlgorithms.EcdsaSha384Signature
                => AddSigningCredentials(new SigningCredentials(new ECDsaSecurityKey(
                    OpenIddictHelpers.CreateEcdsaKey(ECCurve.NamedCurves.nistP384)), algorithm)),

            SecurityAlgorithms.EcdsaSha512 or
            SecurityAlgorithms.EcdsaSha512Signature
                => AddSigningCredentials(new SigningCredentials(new ECDsaSecurityKey(
                    OpenIddictHelpers.CreateEcdsaKey(ECCurve.NamedCurves.nistP521)), algorithm)),
#else
            SecurityAlgorithms.EcdsaSha256 or
            SecurityAlgorithms.EcdsaSha384 or
            SecurityAlgorithms.EcdsaSha512 or
            SecurityAlgorithms.EcdsaSha256Signature or
            SecurityAlgorithms.EcdsaSha384Signature or
            SecurityAlgorithms.EcdsaSha512Signature
                => throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0069)),
#endif

            _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0058))
        };
    }

    /// <summary>
    /// Registers a signing certificate.
    /// </summary>
    /// <param name="certificate">The signing certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningCertificate(X509Certificate2 certificate)
    {
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        // If the certificate is a X.509v3 certificate that specifies at least
        // one key usage, ensure that the certificate key can be used for signing.
        if (certificate.Version >= 3)
        {
            var extensions = certificate.Extensions.OfType<X509KeyUsageExtension>().ToList();
            if (extensions.Count is not 0 && !extensions.Exists(static extension =>
                extension.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature)))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0070));
            }
        }

        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0061));
        }

        return AddSigningKey(new X509SecurityKey(certificate));
    }

    /// <summary>
    /// Registers a signing certificate retrieved from an embedded resource.
    /// </summary>
    /// <param name="assembly">The assembly containing the certificate.</param>
    /// <param name="resource">The name of the embedded resource.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningCertificate(Assembly assembly, string resource, string? password)
#if SUPPORTS_EPHEMERAL_KEY_SETS
        // Note: ephemeral key sets are currently not supported on macOS.
        => AddSigningCertificate(assembly, resource, password, RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ?
            X509KeyStorageFlags.MachineKeySet :
            X509KeyStorageFlags.EphemeralKeySet);
#else
        => AddSigningCertificate(assembly, resource, password, X509KeyStorageFlags.MachineKeySet);
#endif

    /// <summary>
    /// Registers a signing certificate retrieved from an embedded resource.
    /// </summary>
    /// <param name="assembly">The assembly containing the certificate.</param>
    /// <param name="resource">The name of the embedded resource.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <param name="flags">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningCertificate(
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

        return AddSigningCertificate(stream, password, flags);
    }

    /// <summary>
    /// Registers a signing certificate extracted from a stream.
    /// </summary>
    /// <param name="stream">The stream containing the certificate.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningCertificate(Stream stream, string? password)
#if SUPPORTS_EPHEMERAL_KEY_SETS
        // Note: ephemeral key sets are currently not supported on macOS.
        => AddSigningCertificate(stream, password, RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ?
            X509KeyStorageFlags.MachineKeySet :
            X509KeyStorageFlags.EphemeralKeySet);
#else
        => AddSigningCertificate(stream, password, X509KeyStorageFlags.MachineKeySet);
#endif

    /// <summary>
    /// Registers a signing certificate extracted from a stream.
    /// </summary>
    /// <param name="stream">The stream containing the certificate.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <param name="flags">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningCertificate(Stream stream, string? password, X509KeyStorageFlags flags)
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
        return AddSigningCertificate(certificate);
    }

    /// <summary>
    /// Registers a signing certificate retrieved from the X.509 user or machine store.
    /// </summary>
    /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningCertificate(string thumbprint)
    {
        if (string.IsNullOrEmpty(thumbprint))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0065), nameof(thumbprint));
        }

        return AddSigningCertificate(
            GetCertificate(StoreLocation.CurrentUser, thumbprint)  ??
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
    /// Registers a signing certificate retrieved from the specified X.509 store.
    /// </summary>
    /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
    /// <param name="name">The name of the X.509 store.</param>
    /// <param name="location">The location of the X.509 store.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningCertificate(string thumbprint, StoreName name, StoreLocation location)
    {
        if (string.IsNullOrEmpty(thumbprint))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0065), nameof(thumbprint));
        }

        using var store = new X509Store(name, location);
        store.Open(OpenFlags.ReadOnly);

        return AddSigningCertificate(
            store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                .OfType<X509Certificate2>()
                .SingleOrDefault() ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0066)));
    }
    
    /// <summary>
    /// Registers multiple signing certificates.
    /// </summary>
    /// <param name="certificates">The signing certificates.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningCertificates(IEnumerable<X509Certificate2> certificates)
    {
        if (certificates is null)
        {
            throw new ArgumentNullException(nameof(certificates));
        }
        
        return certificates.Aggregate(this, static (builder, certificate) => builder.AddSigningCertificate(certificate));
    }

    /// <summary>
    /// Enables authorization code flow support. For more information
    /// about this specific OAuth 2.0/OpenID Connect flow, visit
    /// https://tools.ietf.org/html/rfc6749#section-4.1 and
    /// http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AllowAuthorizationCodeFlow()
        => Configure(options =>
        {
            options.GrantTypes.Add(GrantTypes.AuthorizationCode);

            options.ResponseTypes.Add(ResponseTypes.Code);
        });

    /// <summary>
    /// Enables client credentials flow support. For more information about this
    /// specific OAuth 2.0 flow, visit https://tools.ietf.org/html/rfc6749#section-4.4.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AllowClientCredentialsFlow()
        => Configure(options => options.GrantTypes.Add(GrantTypes.ClientCredentials));

    /// <summary>
    /// Enables custom grant type support.
    /// </summary>
    /// <param name="type">The grant type associated with the flow.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerBuilder AllowCustomFlow(string type)
    {
        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0071), nameof(type));
        }

        return Configure(options => options.GrantTypes.Add(type));
    }

    /// <summary>
    /// Enables device authorization flow support. For more information about this
    /// specific OAuth 2.0 flow, visit https://tools.ietf.org/html/rfc8628.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AllowDeviceAuthorizationFlow()
        => Configure(options => options.GrantTypes.Add(GrantTypes.DeviceCode));

    /// <summary>
    /// Enables hybrid flow support. For more information
    /// about this specific OpenID Connect flow, visit
    /// http://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AllowHybridFlow()
        => Configure(options =>
        {
            options.GrantTypes.Add(GrantTypes.AuthorizationCode);
            options.GrantTypes.Add(GrantTypes.Implicit);

            options.ResponseTypes.Add(ResponseTypes.Code + ' ' + ResponseTypes.IdToken);
            options.ResponseTypes.Add(ResponseTypes.Code + ' ' + ResponseTypes.IdToken + ' ' + ResponseTypes.Token);
            options.ResponseTypes.Add(ResponseTypes.Code + ' ' + ResponseTypes.Token);
        });

    /// <summary>
    /// Enables implicit flow support. For more information
    /// about this specific OAuth 2.0/OpenID Connect flow, visit
    /// https://tools.ietf.org/html/rfc6749#section-4.2 and
    /// http://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AllowImplicitFlow()
        => Configure(options =>
        {
            options.GrantTypes.Add(GrantTypes.Implicit);

            options.ResponseTypes.Add(ResponseTypes.IdToken);
            options.ResponseTypes.Add(ResponseTypes.IdToken + ' ' + ResponseTypes.Token);
            options.ResponseTypes.Add(ResponseTypes.Token);
        });

    /// <summary>
    /// Enables none flow support. For more information about this specific OAuth 2.0 flow,
    /// visit https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AllowNoneFlow()
        => Configure(options => options.ResponseTypes.Add(ResponseTypes.None));

    /// <summary>
    /// Enables password flow support. For more information about this specific
    /// OAuth 2.0 flow, visit https://tools.ietf.org/html/rfc6749#section-4.3.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AllowPasswordFlow()
        => Configure(options => options.GrantTypes.Add(GrantTypes.Password));

    /// <summary>
    /// Enables refresh token flow support. For more information about this
    /// specific OAuth 2.0 flow, visit https://tools.ietf.org/html/rfc6749#section-6.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AllowRefreshTokenFlow()
        => Configure(options =>
        {
            options.GrantTypes.Add(GrantTypes.RefreshToken);

            options.Scopes.Add(Scopes.OfflineAccess);
        });

    /// <summary>
    /// Sets the relative or absolute URIs associated to the authorization endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetAuthorizationEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        return SetAuthorizationEndpointUris(uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute)).ToArray());
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the authorization endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetAuthorizationEndpointUris(params Uri[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.AuthorizationEndpointUris.Clear();
            options.AuthorizationEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the configuration endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetConfigurationEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        return SetConfigurationEndpointUris(uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute)).ToArray());
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the configuration endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetConfigurationEndpointUris(params Uri[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.ConfigurationEndpointUris.Clear();
            options.ConfigurationEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the device authorization endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetDeviceAuthorizationEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        return SetDeviceAuthorizationEndpointUris(uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute)).ToArray());
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the device authorization endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetDeviceAuthorizationEndpointUris(params Uri[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.DeviceAuthorizationEndpointUris.Clear();
            options.DeviceAuthorizationEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the end session endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetEndSessionEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        return SetEndSessionEndpointUris(uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute)).ToArray());
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the end session endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetEndSessionEndpointUris(params Uri[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.EndSessionEndpointUris.Clear();
            options.EndSessionEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the introspection endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetIntrospectionEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        return SetIntrospectionEndpointUris(uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute)).ToArray());
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the introspection endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetIntrospectionEndpointUris(params Uri[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.IntrospectionEndpointUris.Clear();
            options.IntrospectionEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the JSON Web Key Set endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetJsonWebKeySetEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        return SetJsonWebKeySetEndpointUris(uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute)).ToArray());
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the JSON Web Key Set endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetJsonWebKeySetEndpointUris(params Uri[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.JsonWebKeySetEndpointUris.Clear();
            options.JsonWebKeySetEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the revocation endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetRevocationEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        return SetRevocationEndpointUris(uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute)).ToArray());
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the revocation endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetRevocationEndpointUris(params Uri[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.RevocationEndpointUris.Clear();
            options.RevocationEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the token endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetTokenEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        return SetTokenEndpointUris(uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute)).ToArray());
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the token endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetTokenEndpointUris(params Uri[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.TokenEndpointUris.Clear();
            options.TokenEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the userinfo endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetUserInfoEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        return SetUserInfoEndpointUris(uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute)).ToArray());
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the userinfo endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetUserInfoEndpointUris(params Uri[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.UserInfoEndpointUris.Clear();
            options.UserInfoEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the end-user verification endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned by the device authorization endpoint.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetEndUserVerificationEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        return SetEndUserVerificationEndpointUris(uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute)).ToArray());
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the end-user verification endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned by the device authorization endpoint.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetEndUserVerificationEndpointUris(params Uri[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.EndUserVerificationEndpointUris.Clear();
            options.EndUserVerificationEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Disables JWT access token encryption (this option doesn't affect Data Protection tokens).
    /// Disabling encryption is NOT recommended and SHOULD only be done when issuing tokens
    /// to third-party resource servers/APIs you don't control and don't fully trust.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder DisableAccessTokenEncryption()
        => Configure(options => options.DisableAccessTokenEncryption = true);

    /// <summary>
    /// Disables authorization storage so that ad-hoc authorizations are
    /// not created when an authorization code or refresh token is issued
    /// and can't be revoked to prevent associated tokens from being used.
    /// Using this option is generally NOT recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder DisableAuthorizationStorage()
        => Configure(options => options.DisableAuthorizationStorage = true);

    /// <summary>
    /// Configures OpenIddict to disable rolling refresh tokens so
    /// that refresh tokens used in a token request are not marked
    /// as redeemed and can still be used until they expire. Disabling
    /// rolling refresh tokens is NOT recommended, for security reasons.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder DisableRollingRefreshTokens()
        => Configure(options => options.DisableRollingRefreshTokens = true);

    /// <summary>
    /// Allows processing authorization and token requests that specify scopes that have not
    /// been registered using <see cref="RegisterScopes(string[])"/> or the scope manager.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder DisableScopeValidation()
        => Configure(options => options.DisableScopeValidation = true);

    /// <summary>
    /// Disables sliding expiration. When using this option, refresh tokens
    /// are issued with a fixed expiration date: when they expire, a complete
    /// authorization flow must be started to retrieve a new refresh token.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder DisableSlidingRefreshTokenExpiration()
        => Configure(options => options.DisableSlidingRefreshTokenExpiration = true);

    /// <summary>
    /// Disables token storage, so that no database entry is created
    /// for the tokens and codes returned by the OpenIddict server.
    /// Using this option is generally NOT recommended as it prevents
    /// the tokens and codes from being revoked (if needed).
    /// </summary>
    /// <remarks>
    /// Note: disabling token storage prevents the device authorization flow
    /// from being used and automatically turns sliding expiration off.
    /// </remarks>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder DisableTokenStorage()
        => Configure(options => options.DisableTokenStorage = true);

    /// <summary>
    /// Enables the degraded mode. When the degraded mode is enabled, all the security checks that
    /// depend on the OpenIddict core managers are disabled. This option MUST be enabled with extreme
    /// caution and custom handlers MUST be registered to properly validate OpenID Connect requests.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerBuilder EnableDegradedMode()
        => Configure(options => options.EnableDegradedMode = true);

    /// <summary>
    /// Disables endpoint permissions enforcement. Calling this method is NOT recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder IgnoreEndpointPermissions()
        => Configure(options => options.IgnoreEndpointPermissions = true);

    /// <summary>
    /// Disables grant type permissions enforcement. Calling this method is NOT recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder IgnoreGrantTypePermissions()
        => Configure(options => options.IgnoreGrantTypePermissions = true);

    /// <summary>
    /// Disables response type permissions enforcement. Calling this method is NOT recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder IgnoreResponseTypePermissions()
        => Configure(options => options.IgnoreResponseTypePermissions = true);

    /// <summary>
    /// Disables scope permissions enforcement. Calling this method is NOT recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder IgnoreScopePermissions()
        => Configure(options => options.IgnoreScopePermissions = true);

    /// <summary>
    /// Registers the specified claims as supported claims so
    /// they can be returned as part of the discovery document.
    /// </summary>
    /// <param name="claims">The supported claims.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder RegisterClaims(params string[] claims)
    {
        if (claims is null)
        {
            throw new ArgumentNullException(nameof(claims));
        }

        if (Array.Exists(claims, string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.FormatID0457(nameof(claims)), nameof(claims));
        }

        return Configure(options => options.Claims.UnionWith(claims));
    }

    /// <summary>
    /// Registers the specified prompt values as supported scopes so
    /// they can be returned as part of the discovery document.
    /// </summary>
    /// <param name="values">The supported prompt values.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder RegisterPromptValues(params string[] values)
    {
        if (values is null)
        {
            throw new ArgumentNullException(nameof(values));
        }

        if (Array.Exists(values, string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.FormatID0457(nameof(values)), nameof(values));
        }

        return Configure(options => options.PromptValues.UnionWith(values));
    }

    /// <summary>
    /// Registers the specified scopes as supported scopes so
    /// they can be returned as part of the discovery document.
    /// </summary>
    /// <param name="scopes">The supported scopes.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder RegisterScopes(params string[] scopes)
    {
        if (scopes is null)
        {
            throw new ArgumentNullException(nameof(scopes));
        }

        if (Array.Exists(scopes, string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.FormatID0457(nameof(scopes)), nameof(scopes));
        }

        return Configure(options => options.Scopes.UnionWith(scopes));
    }

    /// <summary>
    /// Configures OpenIddict to force client applications to use Proof Key for Code Exchange
    /// (PKCE) when requesting an authorization code (e.g when using the code or hybrid flows).
    /// When enforced, authorization requests that lack the code_challenge will be rejected.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder RequireProofKeyForCodeExchange()
        => Configure(options => options.RequireProofKeyForCodeExchange = true);

    /// <summary>
    /// Sets the access token lifetime, after which client applications must retrieve
    /// a new access token by making a grant_type=refresh_token token request
    /// or a prompt=none authorization request, depending on the selected flow.
    /// Using long-lived access tokens or tokens that never expire is not recommended.
    /// While discouraged, <see langword="null"/> can be specified to issue tokens that never expire.
    /// </summary>
    /// <param name="lifetime">The access token lifetime.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetAccessTokenLifetime(TimeSpan? lifetime)
        => Configure(options => options.AccessTokenLifetime = lifetime);

    /// <summary>
    /// Sets the authorization code lifetime, after which client applications
    /// are unable to send a grant_type=authorization_code token request.
    /// Using short-lived authorization codes is strongly recommended.
    /// While discouraged, <see langword="null"/> can be specified to issue codes that never expire.
    /// </summary>
    /// <param name="lifetime">The authorization code lifetime.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetAuthorizationCodeLifetime(TimeSpan? lifetime)
        => Configure(options => options.AuthorizationCodeLifetime = lifetime);

    /// <summary>
    /// Sets the device code lifetime, after which client applications are unable to
    /// send a grant_type=urn:ietf:params:oauth:grant-type:device_code token request.
    /// Using short-lived device codes is strongly recommended.
    /// While discouraged, <see langword="null"/> can be specified to issue codes that never expire.
    /// </summary>
    /// <param name="lifetime">The authorization code lifetime.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetDeviceCodeLifetime(TimeSpan? lifetime)
        => Configure(options => options.DeviceCodeLifetime = lifetime);

    /// <summary>
    /// Sets the identity token lifetime, after which client
    /// applications should refuse processing identity tokens.
    /// While discouraged, <see langword="null"/> can be specified to issue tokens that never expire.
    /// </summary>
    /// <param name="lifetime">The identity token lifetime.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetIdentityTokenLifetime(TimeSpan? lifetime)
        => Configure(options => options.IdentityTokenLifetime = lifetime);

    /// <summary>
    /// Sets the refresh token lifetime, after which client applications must get
    /// a new authorization from the user. When sliding expiration is enabled,
    /// a new refresh token is always issued to the client application,
    /// which prolongs the validity period of the refresh token.
    /// While discouraged, <see langword="null"/> can be specified to issue tokens that never expire.
    /// </summary>
    /// <param name="lifetime">The refresh token lifetime.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetRefreshTokenLifetime(TimeSpan? lifetime)
        => Configure(options => options.RefreshTokenLifetime = lifetime);

    /// <summary>
    /// Sets the refresh token reuse leeway, during which rolling refresh tokens marked
    /// as redeemed can still be used to make concurrent refresh token requests.
    /// </summary>
    /// <param name="leeway">The refresh token reuse interval.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetRefreshTokenReuseLeeway(TimeSpan? leeway)
        => Configure(options => options.RefreshTokenReuseLeeway = leeway);

    /// <summary>
    /// Sets the charset used by OpenIddict to generate random user codes.
    /// </summary>
    /// <remarks>
    /// Note: user codes are meant to be entered manually by users. To ensure
    /// they remain easy enough to type even by users with non-Latin keyboards,
    /// user codes generated by OpenIddict only include ASCII digits by default.
    /// </remarks>
    /// <param name="charset">The charset used by OpenIddict to generate random user codes.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetUserCodeCharset(params string[] charset)
    {
        if (charset is null)
        {
            throw new ArgumentNullException(nameof(charset));
        }

        if (charset.Length is < 9)
        {
            throw new ArgumentOutOfRangeException(nameof(charset), SR.FormatID0440(9));
        }

        if (charset.Length != charset.Distinct(StringComparer.Ordinal).Count())
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0436), nameof(charset));
        }

        foreach (var character in charset)
        {
#if SUPPORTS_TEXT_ELEMENT_ENUMERATOR
            // On supported platforms, ensure each character added to the
            // charset represents exactly one grapheme cluster/text element.
            var enumerator = StringInfo.GetTextElementEnumerator(character);
            if (!enumerator.MoveNext() || enumerator.MoveNext())
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0437), nameof(charset));
            }
#else
            // On unsupported platforms, prevent non-ASCII characters from being used.
            if (character.Any(static character => (uint) character > '\x007f'))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0438), nameof(charset));
            }
#endif
        }

        return Configure(options =>
        {
            options.UserCodeCharset.Clear();
            options.UserCodeCharset.UnionWith(charset);
        });
    }

    /// <summary>
    /// Sets the format string used by OpenIddict to display user codes. While not recommended,
    /// a <see langword="null"/> value can be used to disable the user code formatting logic.
    /// </summary>
    /// <remarks>
    /// Note: if no value is explicitly set, a default format using dash separators
    /// is used to make user codes easier to read by the end users.
    /// </remarks>
    /// <param name="format">The string used by OpenIddict to format user codes.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerBuilder SetUserCodeDisplayFormat(string? format)
        => Configure(options => options.UserCodeDisplayFormat = format);

    /// <summary>
    /// Sets the length of the user codes generated by OpenIddict (by default, 12 characters).
    /// </summary>
    /// <param name="length">The length of the user codes generated by OpenIddict.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetUserCodeLength(int length)
    {
        if (length is < 6)
        {
            throw new ArgumentOutOfRangeException(nameof(length), SR.FormatID0439(6));
        }

        return Configure(options => options.UserCodeLength = length);
    }

    /// <summary>
    /// Sets the user code lifetime, after which they'll no longer be considered valid.
    /// Using short-lived device codes is strongly recommended.
    /// While discouraged, <see langword="null"/> can be specified to issue codes that never expire.
    /// </summary>
    /// <param name="lifetime">The authorization code lifetime.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetUserCodeLifetime(TimeSpan? lifetime)
        => Configure(options => options.UserCodeLifetime = lifetime);

    /// <summary>
    /// Sets the issuer URI, which is used as the value of the "issuer" claim and
    /// is returned from the discovery endpoint to identify the authorization server.
    /// </summary>
    /// <param name="uri">The issuer uri.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetIssuer(Uri uri)
    {
        if (uri is null)
        {
            throw new ArgumentNullException(nameof(uri));
        }

        return Configure(options => options.Issuer = uri);
    }

    /// <summary>
    /// Sets the issuer URI, which is used as the value of the "issuer" claim and
    /// is returned from the discovery endpoint to identify the authorization server.
    /// </summary>
    /// <param name="uri">The issuer uri.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetIssuer(
        [StringSyntax(StringSyntaxAttribute.Uri, UriKind.Absolute)] string uri)
    {
        if (string.IsNullOrEmpty(uri))
        {
            throw new ArgumentException(SR.FormatID0366(nameof(uri)), nameof(uri));
        }

        if (!Uri.TryCreate(uri, UriKind.Absolute, out Uri? value) || OpenIddictHelpers.IsImplicitFileUri(value))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof(uri));
        }

        return SetIssuer(value);
    }

    /// <summary>
    /// Configures OpenIddict to use reference tokens, so that the access token payloads
    /// are stored in the database (only an identifier is returned to the client application).
    /// Enabling this option is useful when storing a very large number of claims in the tokens,
    /// but it is RECOMMENDED to enable column encryption in the database or use the ASP.NET Core
    /// Data Protection integration, that provides additional protection against token leakage.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder UseReferenceAccessTokens()
        => Configure(options => options.UseReferenceAccessTokens = true);

    /// <summary>
    /// Configures OpenIddict to use reference tokens, so that the refresh token payloads
    /// are stored in the database (only an identifier is returned to the client application).
    /// Enabling this option is useful when storing a very large number of claims in the tokens,
    /// but it is RECOMMENDED to enable column encryption in the database or use the ASP.NET Core
    /// Data Protection integration, that provides additional protection against token leakage.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder UseReferenceRefreshTokens()
        => Configure(options => options.UseReferenceRefreshTokens = true);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => base.Equals(obj);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override string? ToString() => base.ToString();
}

/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Client;
using OpenIddict.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict client services.
/// </summary>
public sealed class OpenIddictClientBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictClientBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictClientBuilder(IServiceCollection services)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictClientBuilder AddEventHandler<TContext>(
        Action<OpenIddictClientHandlerDescriptor.Builder<TContext>> configuration)
        where TContext : OpenIddictClientEvents.BaseContext
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        // Note: handlers registered using this API are assumed to be custom handlers by default.
        var builder = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
            .SetType(OpenIddictClientHandlerType.Custom);

        configuration(builder);

        return AddEventHandler(builder.Build());
    }

    /// <summary>
    /// Registers an event handler using the specified descriptor.
    /// </summary>
    /// <param name="descriptor">The handler descriptor.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictClientBuilder AddEventHandler(OpenIddictClientHandlerDescriptor descriptor)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictClientBuilder RemoveEventHandler(OpenIddictClientHandlerDescriptor descriptor)
    {
        if (descriptor is null)
        {
            throw new ArgumentNullException(nameof(descriptor));
        }

        Services.RemoveAll(descriptor.ServiceDescriptor.ServiceType);

        Services.PostConfigure<OpenIddictClientOptions>(options =>
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
    /// Amends the default OpenIddict client configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder Configure(Action<OpenIddictClientOptions> configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Registers encryption credentials.
    /// </summary>
    /// <param name="credentials">The encrypting credentials.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddEncryptionCredentials(EncryptingCredentials credentials)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddEncryptionKey(SecurityKey key)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddEncryptionKeys(IEnumerable<SecurityKey> keys)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddDevelopmentEncryptionCertificate()
        => AddDevelopmentEncryptionCertificate(new X500DistinguishedName("CN=OpenIddict Client Encryption Certificate"));

    /// <summary>
    /// Registers (and generates if necessary) a user-specific development encryption certificate.
    /// </summary>
    /// <param name="subject">The subject name associated with the certificate.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddDevelopmentEncryptionCertificate(X500DistinguishedName subject)
    {
        if (subject is null)
        {
            throw new ArgumentNullException(nameof(subject));
        }

        Services.AddOptions<OpenIddictClientOptions>().Configure<IServiceProvider>((options, provider) =>
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
                    certificate.FriendlyName = "OpenIddict Client Development Encryption Certificate";
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddEphemeralEncryptionKey()
        => AddEphemeralEncryptionKey(SecurityAlgorithms.RsaOAEP);

    /// <summary>
    /// Registers a new ephemeral encryption key. Ephemeral encryption keys are automatically
    /// discarded when the application shuts down and payloads encrypted using this key are
    /// automatically invalidated. This method should only be used during development.
    /// On production, using a X.509 certificate stored in the machine store is recommended.
    /// </summary>
    /// <param name="algorithm">The algorithm associated with the encryption key.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddEphemeralEncryptionKey(string algorithm)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddEncryptionCertificate(X509Certificate2 certificate)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddEncryptionCertificate(Assembly assembly, string resource, string? password)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddEncryptionCertificate(
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddEncryptionCertificate(Stream stream, string? password)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddEncryptionCertificate(Stream stream, string? password, X509KeyStorageFlags flags)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddEncryptionCertificate(string thumbprint)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddEncryptionCertificate(string thumbprint, StoreName name, StoreLocation location)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddEncryptionCertificates(IEnumerable<X509Certificate2> certificates)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddSigningCredentials(SigningCredentials credentials)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddSigningKey(SecurityKey key)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddSigningKeys(IEnumerable<SecurityKey> keys)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddDevelopmentSigningCertificate()
        => AddDevelopmentSigningCertificate(new X500DistinguishedName("CN=OpenIddict Client Signing Certificate"));

    /// <summary>
    /// Registers (and generates if necessary) a user-specific development signing certificate.
    /// </summary>
    /// <param name="subject">The subject name associated with the certificate.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddDevelopmentSigningCertificate(X500DistinguishedName subject)
    {
        if (subject is null)
        {
            throw new ArgumentNullException(nameof(subject));
        }

        Services.AddOptions<OpenIddictClientOptions>().Configure<IServiceProvider>((options, provider) =>
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

            if (!certificates.Exists(certificate => certificate.NotBefore < now.LocalDateTime && certificate.NotAfter > now.LocalDateTime))
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
                    certificate.FriendlyName = "OpenIddict Client Development Signing Certificate";
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddEphemeralSigningKey()
        => AddEphemeralSigningKey(SecurityAlgorithms.RsaSha256);

    /// <summary>
    /// Registers a new ephemeral signing key. Ephemeral signing keys are automatically
    /// discarded when the application shuts down and payloads signed using this key are
    /// automatically invalidated. This method should only be used during development.
    /// On production, using a X.509 certificate stored in the machine store is recommended.
    /// </summary>
    /// <param name="algorithm">The algorithm associated with the signing key.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddEphemeralSigningKey(string algorithm)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddSigningCertificate(X509Certificate2 certificate)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddSigningCertificate(Assembly assembly, string resource, string? password)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddSigningCertificate(
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddSigningCertificate(Stream stream, string? password)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddSigningCertificate(Stream stream, string? password, X509KeyStorageFlags flags)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddSigningCertificate(string thumbprint)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddSigningCertificate(string thumbprint, StoreName name, StoreLocation location)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddSigningCertificates(IEnumerable<X509Certificate2> certificates)
    {
        if (certificates is null)
        {
            throw new ArgumentNullException(nameof(certificates));
        }
        
        return certificates.Aggregate(this, static (builder, certificate) => builder.AddSigningCertificate(certificate));
    }

    /// <summary>
    /// Adds a new client registration.
    /// </summary>
    /// <param name="registration">The client registration.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AddRegistration(OpenIddictClientRegistration registration)
    {
        if (registration is null)
        {
            throw new ArgumentNullException(nameof(registration));
        }

        return Configure(options => options.Registrations.Add(registration));
    }

    /// <summary>
    /// Disables token storage, so that no database entry is created
    /// for the tokens and codes returned by the OpenIddict client.
    /// Using this option is generally NOT recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder DisableTokenStorage()
        => Configure(options => options.DisableTokenStorage = true);

    /// <summary>
    /// Disables automatic claim mapping so that the merged principal returned by
    /// OpenIddict after a successful authentication doesn't contain any WS-Federation
    /// claims - exposed by the <see cref="ClaimTypes"/> class - mapped from their
    /// OpenID Connect/JSON Web Token or provider-specific equivalent.
    /// </summary>
    /// <remarks>
    /// Note: OpenID Connect/JSON Web Token or provider-specific claims that are mapped
    /// to their WS-Federation equivalent are never removed from the merged principal
    /// when automatic claim mapping is enabled.
    /// </remarks>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder DisableWebServicesFederationClaimMapping()
        => Configure(options => options.DisableWebServicesFederationClaimMapping = true);

    /// <summary>
    /// Enables authorization code flow support. For more information
    /// about this specific OAuth 2.0/OpenID Connect flow, visit
    /// https://tools.ietf.org/html/rfc6749#section-4.1 and
    /// http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth.
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AllowAuthorizationCodeFlow()
        => Configure(options =>
        {
            options.GrantTypes.Add(GrantTypes.AuthorizationCode);

            options.ResponseTypes.Add(ResponseTypes.Code);
        });

    /// <summary>
    /// Enables client credentials flow support. For more information about this
    /// specific OAuth 2.0 flow, visit https://tools.ietf.org/html/rfc6749#section-4.4.
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AllowClientCredentialsFlow()
        => Configure(options => options.GrantTypes.Add(GrantTypes.ClientCredentials));

    /// <summary>
    /// Enables custom grant type support.
    /// </summary>
    /// <param name="type">The grant type associated with the flow.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictClientBuilder AllowCustomFlow(string type)
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AllowDeviceAuthorizationFlow()
        => Configure(options => options.GrantTypes.Add(GrantTypes.DeviceCode));

    /// <summary>
    /// Enables hybrid flow support. For more information
    /// about this specific OpenID Connect flow, visit
    /// http://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth.
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AllowHybridFlow()
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
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AllowImplicitFlow()
        => Configure(options =>
        {
            options.GrantTypes.Add(GrantTypes.Implicit);

            // Note: response_type=token is not considered secure enough as it allows malicious
            // actors to inject access tokens that were initially issued to a different client.
            // As such, while OpenIddict-based servers allow using response_type=token for backward
            // compatibility with legacy clients, OpenIddict-based clients are deliberately not
            // allowed to negotiate the unsafe and OAuth 2.0-only response_type=token flow.
            //
            // For more information, see https://datatracker.ietf.org/doc/html/rfc6749#section-10.16 and
            // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-19#section-2.1.2.

            options.ResponseTypes.Add(ResponseTypes.IdToken);
            options.ResponseTypes.Add(ResponseTypes.IdToken + ' ' + ResponseTypes.Token);
        });

    /// <summary>
    /// Enables none flow support. For more information about this specific OAuth 2.0 flow,
    /// visit https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none.
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AllowNoneFlow()
        => Configure(options => options.ResponseTypes.Add(ResponseTypes.None));

    /// <summary>
    /// Enables password flow support. For more information about this specific
    /// OAuth 2.0 flow, visit https://tools.ietf.org/html/rfc6749#section-4.3.
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AllowPasswordFlow()
        => Configure(options => options.GrantTypes.Add(GrantTypes.Password));

    /// <summary>
    /// Enables refresh token flow support. For more information about this
    /// specific OAuth 2.0 flow, visit https://tools.ietf.org/html/rfc6749#section-6.
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder AllowRefreshTokenFlow()
        => Configure(options => options.GrantTypes.Add(GrantTypes.RefreshToken));

    /// <summary>
    /// Sets the relative or absolute URIs associated to the post-logout redirection endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder SetPostLogoutRedirectionEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        return SetPostLogoutRedirectionEndpointUris(uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute)).ToArray());
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the post-logout redirection endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder SetPostLogoutRedirectionEndpointUris(params Uri[] uris)
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
            options.PostLogoutRedirectionEndpointUris.Clear();
            options.PostLogoutRedirectionEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the redirection endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// </summary>
    /// <remarks>
    /// Note: to mitigate mix-up attacks, it's recommended to use a unique redirection endpoint
    /// URI per provider, unless all the registered providers support returning an "iss" parameter
    /// containing their identity as part of authorization responses. For more information,
    /// see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.4.
    /// </remarks>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder SetRedirectionEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        if (uris is null)
        {
            throw new ArgumentNullException(nameof(uris));
        }

        return SetRedirectionEndpointUris(uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute)).ToArray());
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the redirection endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// </summary>
    /// <remarks>
    /// Note: to mitigate mix-up attacks, it's recommended to use a unique redirection endpoint
    /// URI per provider, unless all the registered providers support returning an "iss" parameter
    /// containing their identity as part of authorization responses. For more information,
    /// see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.4.
    /// </remarks>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder SetRedirectionEndpointUris(params Uri[] uris)
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
            options.RedirectionEndpointUris.Clear();
            options.RedirectionEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the client assertion lifetime, after which backchannel requests
    /// using an expired client assertion should be automatically rejected by the server.
    /// Using long-lived client assertion or assertions that never expire is not recommended.
    /// While discouraged, <see langword="null"/> can be specified to issue assertions that never expire.
    /// </summary>
    /// <param name="lifetime">The access token lifetime.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder SetClientAssertionLifetime(TimeSpan? lifetime)
        => Configure(options => options.ClientAssertionLifetime = lifetime);

    /// <summary>
    /// Sets the state token lifetime, after which authorization callbacks
    /// using an expired state token will be automatically rejected by OpenIddict.
    /// Using long-lived state tokens or tokens that never expire is not recommended.
    /// While discouraged, <see langword="null"/> can be specified to issue tokens that never expire.
    /// </summary>
    /// <param name="lifetime">The access token lifetime.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public OpenIddictClientBuilder SetStateTokenLifetime(TimeSpan? lifetime)
        => Configure(options => options.StateTokenLifetime = lifetime);

    /// <summary>
    /// Sets the client URI, which is used as the value of the "issuer" claim.
    /// </summary>
    /// <param name="uri">The client URI.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictClientBuilder SetClientUri(Uri uri)
    {
        if (uri is null)
        {
            throw new ArgumentNullException(nameof(uri));
        }

        return Configure(options => options.ClientUri = uri);
    }

    /// <summary>
    /// Sets the client URI, which is used as the value of the "issuer" claim.
    /// </summary>
    /// <param name="uri">The client URI.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictClientBuilder SetClientUri(
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

        return SetClientUri(value);
    }

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

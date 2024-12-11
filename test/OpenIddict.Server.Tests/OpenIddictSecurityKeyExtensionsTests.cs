using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using Xunit.Abstractions;

namespace OpenIddict.Server.Tests
{
    public class OpenIddictSecurityKeyExtensionsTests
    {
        private readonly ITestOutputHelper _testOutputHelper;
        private readonly DateTime _fakeNow = new(2024, 12, 6);

        private readonly X509SigningCredentials _fakeX509Credentials1;
        private readonly X509SigningCredentials _fakeX509Credentials2;
        private readonly X509SigningCredentials _fakeX509Credentials3;
        private readonly X509SigningCredentials _fakeX509Credentials4;
        private readonly X509SigningCredentials _fakeX509Credentials5;

        private readonly SigningCredentials _fakeSymmetricSecurityKey1;
        private readonly SigningCredentials _fakeAsymmetricSecurityKey1;

        public OpenIddictSecurityKeyExtensionsTests(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            
            _fakeX509Credentials1 = new X509SigningCredentials(ReadCert("OpenIddict.Server.Tests.Certificate.pfx"))
                { Key = { KeyId = $"_fakeX509Credentials1" } };
            _fakeX509Credentials2 = new X509SigningCredentials(ReadCert("OpenIddict.Server.Tests.Certificate_110526_101226.pem"))
                { Key = { KeyId = $"_fakeX509Credentials2" } };
            _fakeX509Credentials3 = new X509SigningCredentials(ReadCert("OpenIddict.Server.Tests.Certificate_220726_050527.pem"))
                { Key = { KeyId = $"_fakeX509Credentials3" } };
            _fakeX509Credentials4 = new X509SigningCredentials(ReadCert("OpenIddict.Server.Tests.Certificate_220726_091227.pem"))
                { Key = { KeyId = $"_fakeX509Credentials4" } };
            _fakeX509Credentials5 = new X509SigningCredentials(ReadCert("OpenIddict.Server.Tests.Certificate_221226_230827.pem"))
                { Key = { KeyId = $"_fakeX509Credentials5" } };
            
            byte[] signingKey = "SOMEPOWERFULSIGINGKEY"u8.ToArray();
            _fakeSymmetricSecurityKey1 = new SigningCredentials(new SymmetricSecurityKey(signingKey), SecurityAlgorithms.HmacSha256Signature);
            _fakeAsymmetricSecurityKey1 = new SigningCredentials(GenerateAsymmetricKey(2048, "_fakeAsymmetricSecurityKey1"), SecurityAlgorithms.RsaSha256);
        }

        private static RsaSecurityKey GenerateAsymmetricKey(int keySize, string keyId)
        {
            using RSA rsa = RSA.Create();
            rsa.KeySize = keySize;
            RSAParameters parameters = rsa.ExportParameters(true);
            return new RsaSecurityKey(parameters) { KeyId = String.IsNullOrWhiteSpace(keyId) ? Guid.NewGuid().ToString() : keyId };
        }
        
        private static X509Certificate2? ReadCert(string file)
        {
            byte[] embeddedCert;
            Assembly thisAssembly = typeof(OpenIddictSigningCredentialListTests).GetTypeInfo().Assembly;
            
            using (Stream? certStream = thisAssembly.GetManifestResourceStream(file))
            {
                if (certStream == null) return null;
                
                using MemoryStream? buffer = new();
                certStream.CopyTo(buffer);
        
                embeddedCert = buffer.ToArray();
            }
            
            // TODO Replace with version specific initialisation for latest version of dotnet as this ctor is obsoleted in latest dotnet
#pragma warning disable SYSLIB0057
            return new X509Certificate2(embeddedCert, "OpenIddict");
#pragma warning restore SYSLIB0057
        }
        
        [Fact]
        public void Compare_WhenAsymmetricKey_AndX509AndSymmetricPresent_ShouldPreferSymmetric()
        {
            List<SigningCredentials> existingCerts = [
                _fakeSymmetricSecurityKey1, _fakeAsymmetricSecurityKey1, _fakeX509Credentials1
            ];

            existingCerts.Sort((x, y) =>
                OpenIddictSecurityKeyExtensions.Compare(x.Key ?? new JsonWebKey(), y.Key ?? new JsonWebKey(),
                    _fakeNow));
            
            SigningCredentials[] ary = existingCerts.ToArray();

            Assert.Same(_fakeSymmetricSecurityKey1, Get(0));
            Assert.Same(_fakeX509Credentials1, Get(1));
            Assert.Same(_fakeAsymmetricSecurityKey1, Get(2));
            return;

            SigningCredentials? Get(int index) => ary[index];
        }
        
        [Fact]
        public void Compare_WhenSymmetricKeyAdded_AndOtherX509_ShouldPreferSymmetric()
        {
            List<SigningCredentials> existingCerts = [
                _fakeX509Credentials2, _fakeX509Credentials1
            ];

            existingCerts.Sort((x, y) =>
                OpenIddictSecurityKeyExtensions.Compare(x.Key ?? new JsonWebKey(), y.Key ?? new JsonWebKey(),
                    _fakeNow));
            
            existingCerts.Add(_fakeSymmetricSecurityKey1);
            
            existingCerts.Sort((x, y) =>
                OpenIddictSecurityKeyExtensions.Compare(x.Key ?? new JsonWebKey(), y.Key ?? new JsonWebKey(),
                    _fakeNow));
            
            SigningCredentials[] ary = existingCerts.ToArray();

            Assert.Same(_fakeSymmetricSecurityKey1, Get(0));
            Assert.Same(_fakeX509Credentials1, Get(1));
            Assert.Same(_fakeX509Credentials2, Get(2));
            return;

            SigningCredentials? Get(int index) => ary[index];
        }
        
        [Fact]
        public void Compare_WhenAllX509Certs_AddedInRandomOrder_ShouldOrderByLongestLived_AndIfActive()
        {
            List<X509SigningCredentials> existingCerts = [
                _fakeX509Credentials4, _fakeX509Credentials5, _fakeX509Credentials1
            ];

            existingCerts.Sort((x, y) =>
                OpenIddictSecurityKeyExtensions.Compare(x.Key ?? new JsonWebKey(), y.Key ?? new JsonWebKey(),
                    _fakeNow));
            
            existingCerts.Add(_fakeX509Credentials2);
            
            existingCerts.Sort((x, y) =>
                OpenIddictSecurityKeyExtensions.Compare(x.Key ?? new JsonWebKey(), y.Key ?? new JsonWebKey(),
                    _fakeNow));
            
            X509SigningCredentials[] ary = existingCerts.ToArray();

            Assert.Equal(_fakeX509Credentials1.Key.KeyId, Get(0)?.Key.KeyId);
            Assert.Equal(_fakeX509Credentials5.Key.KeyId, Get(1)?.Key.KeyId);
            Assert.Equal(_fakeX509Credentials4.Key.KeyId, Get(2)?.Key.KeyId);
            Assert.Equal(_fakeX509Credentials2.Key.KeyId, Get(3)?.Key.KeyId);
            return;

            X509SigningCredentials? Get(int index) => ary[index];
        }
        
        [Fact]
        public void Compare_WhenAddedInRandomOrder_ShouldOrderByLongestLived()
        {
            List<X509SigningCredentials> existingCerts = [
                _fakeX509Credentials4, _fakeX509Credentials1
            ];

            existingCerts.Sort((x, y) =>
                OpenIddictSecurityKeyExtensions.Compare(x.Key ?? new JsonWebKey(), y.Key ?? new JsonWebKey(),
                    _fakeNow));
            
            existingCerts.AddRange([_fakeX509Credentials5, _fakeX509Credentials2]);
            
            X509SigningCredentials[] ary = existingCerts.ToArray();

            Assert.Equal(_fakeX509Credentials1.Key.KeyId, Get(0)?.Key.KeyId);
            Assert.Equal(_fakeX509Credentials4.Key.KeyId, Get(1)?.Key.KeyId);
            Assert.Equal(_fakeX509Credentials5.Key.KeyId, Get(2)?.Key.KeyId);
            Assert.Equal(_fakeX509Credentials2.Key.KeyId, Get(3)?.Key.KeyId);
            return;

            X509SigningCredentials? Get(int index) => ary[index];
        }

        private void Print(X509SigningCredentials? creeds)
        {
            _testOutputHelper.WriteLine($"{creeds?.Key.KeyId}: {creeds?.Certificate.NotBefore:U} -> {creeds?.Certificate.NotAfter:U} [{(creeds?.Certificate.NotAfter - creeds?.Certificate.NotBefore)?.Days}]");
        }
    }
}
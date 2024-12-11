using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server.Tests.Helpers;
using Xunit;
using Xunit.Abstractions;

namespace OpenIddict.Server.Tests
{
    public class OpenIddictSigningCredentialListTests(ITestOutputHelper testOutputHelper)
    {
        private readonly DateTime _fakeNow = new(2024, 12, 6);

        private OpenIddictSigningCredentialList CreateSut(SigningCredentials[]? initialValues = null)
        {
            return new OpenIddictSigningCredentialList(initialValues ?? [], new OpenIddictSigningCredentialsComparer(() => _fakeNow));
        }
        
        [Fact]
        public void Add_WhenNoKidSet_ShouldAddOne()
        {
            X509Certificate2? fakeCert = X509Certificate2Helpers.ReadCert("OpenIddict.Server.Tests.Certificate.pfx");
            X509SigningCredentials? credential = new(fakeCert) { Key = { KeyId = null } };

            OpenIddictSigningCredentialList? sut = CreateSut();
            
            sut.Add(credential);
            
            Assert.NotNull(sut.ToArray()[0].Key.KeyId);
            Assert.NotEmpty(sut.ToArray()[0].Key.KeyId);
        }
        
        [Fact]
        public void AddRange_WhenNoKidSet_ShouldAddThem()
        {
            X509SigningCredentials fakeCert1 = new(X509Certificate2Helpers.ReadCert("OpenIddict.Server.Tests.Certificate.pfx")) { Key = { KeyId = null } };
            X509SigningCredentials fakeCert2 = new(X509Certificate2Helpers.ReadCert("OpenIddict.Server.Tests.Certificate_110526_101226.pem")) { Key = { KeyId = null } };
            
            Print(fakeCert1);
            Print(fakeCert2);

            OpenIddictSigningCredentialList sut = CreateSut([]);
            
            sut.AddRange([fakeCert1, fakeCert2]);
            
            SigningCredentials[] ary = sut.ToArray();
            
            Assert.NotNull(sut.ToArray()[0].Key.KeyId);
            Assert.NotEmpty(sut.ToArray()[0].Key.KeyId);
            Assert.NotNull(sut.ToArray()[1].Key.KeyId);
            Assert.NotEmpty(sut.ToArray()[1].Key.KeyId);
        }

        private void Print(X509SigningCredentials? creeds)
        {
            testOutputHelper.WriteLine($"{creeds?.Key.KeyId}: {creeds?.Certificate.NotBefore:U} -> {creeds?.Certificate.NotAfter:U} [{(creeds?.Certificate.NotAfter - creeds?.Certificate.NotBefore)?.Days}]");
        }
    }
}
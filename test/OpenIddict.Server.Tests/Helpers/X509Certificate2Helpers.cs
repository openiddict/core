using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace OpenIddict.Server.Tests.Helpers
{
    public static class X509Certificate2Helpers
    {
        public static X509Certificate2? ReadCert(string file)
        {
            byte[] embeddedCert;
            Assembly thisAssembly = typeof(OpenIddictSigningOpenIddictCredentialListTests).GetTypeInfo().Assembly;
            
            using (Stream? certStream = thisAssembly.GetManifestResourceStream(file))
            {
                if (certStream == null) return null;
                
                using MemoryStream? buffer = new();
                certStream.CopyTo(buffer);
        
                embeddedCert = buffer.ToArray();
            }
            
            // TODO Replace with version agnostic initialisation, obsoleted in latest version of dotnet
#pragma warning disable SYSLIB0057
            return new X509Certificate2(embeddedCert, "OpenIddict");
#pragma warning restore SYSLIB0057
        }
    }
}
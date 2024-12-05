using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Server
{
    public class OpenIddictSigningCredentialsComparer(Func<DateTime> getNow): IComparer<SigningCredentials>
    {
        public static OpenIddictSigningCredentialsComparer DefaultInstance = new OpenIddictSigningCredentialsComparer(
            () =>
            {
                DateTime now = (
#if SUPPORTS_TIME_PROVIDER
                    TimeProvider.System?.GetUtcNow().DateTime ??
#endif
                    DateTimeOffset.UtcNow
                    ).LocalDateTime;

                return now;
            });
        
        public int Compare(SigningCredentials? x, SigningCredentials? y)
        {
            return OpenIddictSecurityKeyExtensions.Compare(x?.Key ?? new JsonWebKey(), y?.Key ?? new JsonWebKey(), getNow());
        }
    }
}
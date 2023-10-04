using OpenIddict.EntityFrameworkCore.Models;

namespace OpenIdDictMvcContext.Data
{
    public class OidcToken: OpenIddictEntityFrameworkCoreToken<string, OidcApplication, OidcAuthorization>
    {
    }
}

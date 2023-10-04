using OpenIddict.EntityFrameworkCore.Models;

namespace OpenIdDictMvcContext.Data
{
    public class OidcAuthorization: OpenIddictEntityFrameworkCoreAuthorization<string, OidcApplication, OidcToken>
    {
    }
}

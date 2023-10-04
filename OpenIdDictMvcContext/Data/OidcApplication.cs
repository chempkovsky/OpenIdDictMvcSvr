using OpenIddict.EntityFrameworkCore.Models;

namespace OpenIdDictMvcContext.Data
{
    public class OidcApplication: OpenIddictEntityFrameworkCoreApplication<string, OidcAuthorization, OidcToken>
    {
    }
}

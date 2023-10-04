using Microsoft.AspNetCore.Identity;

namespace OpenIdDictMvcContext.Data
{
    public class OidcIdentityRole: IdentityRole
    {
        public OidcIdentityRole():base() { }
        public OidcIdentityRole(string roleName) : base(roleName) { }
    }
}

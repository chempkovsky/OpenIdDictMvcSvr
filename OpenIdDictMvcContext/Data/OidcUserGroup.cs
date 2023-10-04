using Microsoft.AspNetCore.Identity;
using System.Security.Cryptography;

namespace OpenIdDictMvcContext.Data
{
    public class OidcUserGroup : OidcUserGroup<string, OidcIdentityUser, OidcGroup>
    {
    }


    public class OidcUserGroup<TKey, TOidcIdentityUser, TOidcGroup> 
        where TKey : notnull, IEquatable<TKey>
        where TOidcIdentityUser: class
        where TOidcGroup : class
    {
        public virtual TKey? OidcUserId { get; set; }
        public virtual TKey? OidcGroupId { get; set; }
        public virtual TOidcGroup Group { get; set; } = null!;
        public virtual TOidcIdentityUser User { get; set; } = null!;
    }
}

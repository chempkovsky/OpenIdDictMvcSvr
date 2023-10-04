using Microsoft.AspNetCore.Identity;

namespace OpenIdDictMvcContext.Data
{
    public class OidcIdentityUser : OidcIdentityUser<string, OidcUserGroup, OidcUserScope>
    {
        public OidcIdentityUser()
        {
            Id = Guid.NewGuid().ToString();
            SecurityStamp = Guid.NewGuid().ToString();
        }

        public OidcIdentityUser(string userName) : this()
        {
            UserName = userName;
        }

    }

    public class OidcIdentityUser<TKey, TOidcUserGroup, TOidcUserScope> : IdentityUser<TKey> 
        where TKey : notnull, IEquatable<TKey>
        where TOidcUserGroup : class
        where TOidcUserScope : class
    {
        public OidcIdentityUser(): base() { }
        public OidcIdentityUser(string userName): base(userName) { }
        public virtual ICollection<TOidcUserGroup> UserGroups { get; } = new List<TOidcUserGroup>();
        public virtual ICollection<TOidcUserScope> UserScopes { get; } = new List<TOidcUserScope>();
    }
}

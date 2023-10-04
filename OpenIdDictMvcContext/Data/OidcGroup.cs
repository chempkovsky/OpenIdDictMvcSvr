using Microsoft.Extensions.Hosting;
using System.Xml.Linq;

namespace OpenIdDictMvcContext.Data
{
    public class OidcGroup: OidcGroup<string, OidcUserGroup, OidcGroupScope>
    {
        public OidcGroup() {
            OidcGroupId = Guid.NewGuid().ToString();
        }

        public OidcGroup(string groupName) : this()
        {
            OidcGroupName = groupName;
        }

    }

    public class OidcGroup<TKey, TOidcUserGroup, TOidcGroupScope> 
        where TKey : notnull, IEquatable<TKey>
        where TOidcUserGroup : class
        where TOidcGroupScope : class
    {
        public virtual TKey? OidcGroupId { get; set; }
        public virtual string? OidcGroupName { get; set; }
        public virtual string? OidcGroupDisplayName { get; set; }
        public virtual ICollection<TOidcUserGroup> UserGroups { get; } = new List<TOidcUserGroup>();
        public virtual ICollection<TOidcGroupScope> GroupScopes { get; } = new List<TOidcGroupScope>();
    }
}

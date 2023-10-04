using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpenIdDictMvcLib.Dto
{
    public class OidcUserJDto
    {
        public string? Email { get; set; }
        public string? Password { get; set; }
        public string[]? UserRoles { get; set; }
        public string[]? UserGroups { get; set; }
        public List<OidcScopeJDto>? UserScopes { get; set; }
    }
}

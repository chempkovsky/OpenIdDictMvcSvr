using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpenIdDictMvcLib.Dto
{
    public class OidcScopeADto
    {
        public HashSet<string> OidcScopes { get; set; } = new();
        public HashSet<string> OidcAudiences { get; set; } = new();
    }
}

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpenIdDictMvcLib.Dto
{
    public class OidcGroupJDto
    {

        [Display(Name = "Group Name")]
        [Required(ErrorMessage = "The Group Name field is required.")]
        public string? OidcGroupName { get; set; }

        [Display(Name = "Group Display Name")]
        public string? OidcGroupDisplayName { get; set; }

        public List<OidcScopeJDto>? OidcScopes { get; set; }
    }
}

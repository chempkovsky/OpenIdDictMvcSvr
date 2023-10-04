using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpenIdDictMvcLib.Dto
{
    public class OidcScopeJDto
    {

        [Display(Name = "App Name")]
        [Required(ErrorMessage = "The App Name field is required.")]
        public string? OidcAppName { get; set; }

        [Display(Name = "Scopes")]
        [Required(ErrorMessage = "The Scopes field is required.")]
        public string? OidcScopes { get; set; }

        [Display(Name = "Audiences")]
        public string? OidcAudiences { get; set; }
    }
}

using System.ComponentModel.DataAnnotations;

namespace OpenIdDictMvcLib.Dto
{
    public class OidcScopeDto
    {
        [Display(Name = "Parent ID")]
        [Required(ErrorMessage = "The Parent ID field is required.")]
        public string? OidcParentId { get; set; }

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

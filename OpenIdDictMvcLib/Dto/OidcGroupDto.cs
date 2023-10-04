using System.ComponentModel.DataAnnotations;

namespace OpenIdDictMvcLib.Dto
{
    public class OidcGroupDto
    {
        [Display(Name = "Group ID")]
        public string? OidcGroupId { get; set; }

        [Display(Name = "Group Name")]
        [Required(ErrorMessage = "The Group Name field is required.")]
        public string? OidcGroupName { get; set; }

        [Display(Name = "Group Display Name")]
        public string? OidcGroupDisplayName { get; set; }
    }
}

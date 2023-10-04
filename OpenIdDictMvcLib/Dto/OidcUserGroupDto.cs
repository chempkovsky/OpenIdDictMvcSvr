using System.ComponentModel.DataAnnotations;

namespace OpenIdDictMvcLib.Dto
{
    public class OidcUserGroupDto
    {
        [Display(Name = "User Id")]
        public string? OidcUserId { get; set; }
        [Display(Name = "Group Id")]
        public string? OidcGroupId { get; set; }
        [Display(Name = "Group Name")]
        public string? OidcGroupName { get; set; }
        [Display(Name = "Display Name")]
        public string? OidcGroupDisplayName { get; set; }
    }
}

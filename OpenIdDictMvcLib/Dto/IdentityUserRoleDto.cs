using System.ComponentModel.DataAnnotations;

namespace OpenIdDictMvcLib.Dto
{
    public class IdentityUserRoleDto
    {
        [Display(Name = "User ID")]
        [Required(ErrorMessage = "The User Id field is required.")]
        public string Id { get; set; } = null!;


        [Required(ErrorMessage = "The Role Name field is required.")]
        [StringLength(256)]
        [Display(Name = "Role Name")]
        public string? RoleName { get; set; }
    }
}

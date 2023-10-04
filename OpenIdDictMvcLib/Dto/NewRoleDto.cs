using System.ComponentModel.DataAnnotations;

namespace OpenIdDictMvcLib.Dto
{
    public class NewRoleDto
    {
        [Required(ErrorMessage = "The Role Name field is required.")]
        [StringLength(256)]
        [Display(Name = "Role Name")]
        public string? Name { get; set; }
    }
}

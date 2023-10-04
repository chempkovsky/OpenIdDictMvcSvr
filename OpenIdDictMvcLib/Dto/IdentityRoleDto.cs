using System.ComponentModel.DataAnnotations;

namespace OpenIdDictMvcLib.Dto
{
    public class IdentityRoleDto
    {
        //[Key]
        [Display(Name = "Role ID")]
        [Required(ErrorMessage = "The Role Id field is required.")]
        public string Id { get; set; } = null!;

        [Required(ErrorMessage = "The Role Name field is required.")]
        [StringLength(256)]
        [Display(Name = "Role Name")]
        public string? Name { get; set; }

        [StringLength(256)]
        [Display(Name = "Normalized Name")]
        public string? NormalizedName { get; set; }

        [Display(Name = "Concurrency Stamp")]
        public string? ConcurrencyStamp { get; set; }
    }
}

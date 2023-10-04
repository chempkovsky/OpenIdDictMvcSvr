using System.ComponentModel.DataAnnotations;

namespace OpenIdDictMvcLib.Dto
{
    public class IdentityUserDto
    {
        [Display(Name = "User ID")]
        [Required(ErrorMessage = "The User Id field is required.")]
        public string Id { get; set; } = null!;

        
        [Required(ErrorMessage = "The User Name field is required.")]
        [StringLength(256)]
        [Display(Name = "User Name")]
        public string? UserName { get; set; }

        [StringLength(256)]
        [Display(Name = "Normalized Name")]
        public string? NormalizedUserName { get; set; }

        [Required(ErrorMessage = "The Email field is required.")]
        [StringLength(256)]
        [Display(Name = "Email")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "The Normalized Email field is required.")]
        [StringLength(256)]
        [Display(Name = "Normalized Email")]
        public string? NormalizedEmail { get; set; }

        [Display(Name = "Email confirmed")]
        public bool EmailConfirmed { get; set; }

        [Display(Name = "Password Hash")]
        public string? PasswordHash { get; set; }

        [Display(Name = "Security Stamp")]
        public string? SecurityStamp { get; set; }

        [Display(Name = "Concurrency Stamp")]
        public string? ConcurrencyStamp { get; set; }
        
        [Display(Name = "Phone Number")]
        public string? PhoneNumber { get; set; }

        [Display(Name = "Phone Number Confirmed")]
        public bool PhoneNumberConfirmed { get; set; }

        [Display(Name = "Two Factor Enabled")]
        public bool TwoFactorEnabled { get; set; }

        [Display(Name = "Lockout End")]
        public DateTimeOffset? LockoutEnd { get; set; }
        
        [Display(Name = "Lockout Enabled")]
        public bool LockoutEnabled { get; set; }

    }
}

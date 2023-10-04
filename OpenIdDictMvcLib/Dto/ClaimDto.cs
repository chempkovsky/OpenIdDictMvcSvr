using System.ComponentModel.DataAnnotations;

namespace OpenIdDictMvcLib.Dto
{
    public class ClaimDto
    {
        [Display(Name = "Claim Type")]
        [Required(ErrorMessage = "The Claim Type field is required.")]
        public string? ClaimType { get; set; }

        [Display(Name = "Issuer")]
        public string? Issuer { get; set; }

        [Display(Name = "Original Issuer")]
        public string? OriginalIssuer { get; set; }

        [Display(Name = "Claim Value")]
        public string? ClaimValue { get; set; }

        [Display(Name = "Claim Value Type")]
        public string? ClaimValueType { get; set; }   
    }
}

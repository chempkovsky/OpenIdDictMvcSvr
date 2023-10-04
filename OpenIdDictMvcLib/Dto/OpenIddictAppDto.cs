using System.ComponentModel.DataAnnotations;

namespace OpenIdDictMvcLib.Dto
{
    public class OpenIddictAppDto
    {
        [Display(Name = "App ID")]
        public string? Id { get; set; } 

        [Display(Name = "Client ID")]
        public string? ClientId { get; set; }

        [Display(Name = "Display Name")]
        public string? DisplayName { get; set; }

        [Display(Name = "Client Type")]
        public string? ClientType { get; set; }

        [Display(Name = "Consent Type")]
        public string? ConsentType { get; set; }
    }
}

using System.ComponentModel.DataAnnotations;

namespace OpenIdDictMvcLib.Dto
{
    public class OpenIddictAuthDto
    {
        [Display(Name = "Authorization Id")]
        public string? AuthorizationId { get; set; }

        [Display(Name = "Application Id")]
        public string? ApplicationId { get; set; }

        [Display(Name = "Creation Date")]
        public DateTimeOffset? CreationDate { get; set; }

        [Display(Name = "Status")]
        public string? Status { get; set; }

        [Display(Name = "Subject")]
        public string? Subject { get; set; }

        [Display(Name = "Type")]
        public string? AuthorizationType { get; set; }
    }
}

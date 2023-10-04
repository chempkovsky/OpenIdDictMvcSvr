using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using System.ComponentModel.DataAnnotations;

namespace OpenIdDictMvcLib.Dto
{
    public class VerifyViewDto
    {
        [Display(Name = "Application")]
        public string? ApplicationName { get; set; }

        [BindNever, Display(Name = "Error")]
        public string? Error { get; set; }

        [BindNever, Display(Name = "Error description")]
        public string? ErrorDescription { get; set; }

        [Display(Name = "Scope")]
        public string? Scope { get; set; }

        [FromQuery(Name = OpenIddictConstants.Parameters.UserCode)]
        [Display(Name = "User code")]
        public string? UserCode { get; set; }

        public List<string> ScopesToAuthorize { get; set; } = new List<string>();
    }
}

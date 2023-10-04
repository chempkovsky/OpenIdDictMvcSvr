using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using System.ComponentModel.DataAnnotations;

namespace OpenIdDictMvcLib.Dto
{
    public class VerifyDto
    {
        [Display(Name = "Application")]
        public string ApplicationName { get; set; } = null!;

        [BindNever, Display(Name = "Error")]
        public string Error { get; set; } = null!;

        [BindNever, Display(Name = "Error description")]
        public string ErrorDescription { get; set; } = null!;

        [Display(Name = "Scope")]
        public string Scope { get; set; } = null!;

        [FromQuery(Name = OpenIddictConstants.Parameters.UserCode)]
        [Display(Name = "User code")]
        public string UserCode { get; set; } = null!;
    }
}

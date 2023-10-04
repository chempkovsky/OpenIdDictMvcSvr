using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using OpenIddict.Abstractions;
using System.ComponentModel.DataAnnotations;

namespace OpenIdDictMvcLib.Dto
{
    public class AuthorizeDto
    {
        public string ApplicationName { get; set; } = "";
        public string? LocalizedApplicationName { get; set; }
        public List<string> ScopesToAuthorize { get; set; } = new List<string>();

        [BindNever, Display(Name = "Error")]
        public string Error { get; set; } = null!;

        [BindNever, Display(Name = "Error description")]
        public string ErrorDescription { get; set; } = null!;

        [FromQuery(Name = OpenIddictConstants.Parameters.UserCode)]
        [Display(Name = "User code")]
        public string UserCode { get; set; } = null!;

    }
}

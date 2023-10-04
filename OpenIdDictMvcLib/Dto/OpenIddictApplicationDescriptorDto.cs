﻿using System.ComponentModel.DataAnnotations;
using System.Diagnostics.Contracts;

namespace OpenIdDictMvcLib.Dto
{
    public class OpenIddictApplicationDescriptorDto
    {
        [Display(Name = "Application Id")]
        public string? AppId { get; set; }

        /// <summary>
        /// Gets or sets the client identifier associated with the application.
        /// </summary>
        [Required(ErrorMessage = "The Client Id field is required.")]
        [StringLength(100)]
        [Display(Name = "Client Id")]
        public string? ClientId { get; set; }

        [Display(Name = "Client Secret")]
        public string? ClientSecret { get; set;}

        /// <summary>
        /// Gets or sets the display name associated with the application.
        /// </summary>
        [Display(Name = "Display Name")]
        public string? DisplayName { get; set; } 

        /// <summary>
        /// Gets or sets the consent type associated with the application.
        /// </summary>
        [Display(Name = "Consent Type")]
        public string? ConsentType { get; set; } = null!;

        /// <summary>
        /// Gets or sets the application type associated with the application.
        /// </summary>
        [Display(Name = "Client Type")]
        public string? ClientType { get; set; }


        /// <summary>
        /// Gets or sets the application type associated with the application.
        /// </summary>
        [Display(Name = "Permissions")]
        public string[]? Permissions { get; set; } 

        /// <summary>
        /// Gets the requirements associated with the application.
        /// </summary>
        [Display(Name = "Custom Permissions")]
        public string[]? CustomPermissions { get; set; } 


        /// <summary>
        /// Gets the requirements associated with the application.
        /// </summary>
        [Display(Name = "Requirements")]
        public string[]? Requirements { get; set; } 


        [Display(Name = "Redirect Uris")]
        public string[]? RedirectUris { get; set; }

        [Display(Name = "Post Logout Redirect Uris")]
        public string[]? PostLogoutRedirectUris { get; set; }

        [Display(Name = "Display Names")]
        public List<KeyValuePair<string, string>>? DisplayNames { get; set; }

    }
}

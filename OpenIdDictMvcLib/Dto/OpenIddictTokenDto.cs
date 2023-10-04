using System.ComponentModel.DataAnnotations;

namespace OpenIdDictMvcLib.Dto
{
    public class OpenIddictTokenDto
    {
        /// <summary>
        /// Gets or sets the application identifier associated with the token.
        /// </summary>
        [Display(Name = "Token Id")]
        public string? TokenId { get; set; } = null!;

        /// <summary>
        /// Gets or sets the application identifier associated with the token.
        /// </summary>
        [Display(Name = "Application Id")]
        public string? ApplicationId { get; set; }

        /// <summary>
        /// Gets or sets the authorization identifier associated with the token.
        /// </summary>
        [Display(Name = "Authorization Id")]
        public string? AuthorizationId { get; set; }

        /// <summary>
        /// Gets or sets the creation date associated with the token.
        /// </summary>
        [Display(Name = "Creation Date")]
        public DateTimeOffset? CreationDate { get; set; }

        /// <summary>
        /// Gets or sets the expiration date associated with the token.
        /// </summary>
        [Display(Name = "Expiration Date")]
        public DateTimeOffset? ExpirationDate { get; set; }

        /// <summary>
        /// Gets or sets the redemption date associated with the token.
        /// </summary>
        [Display(Name = "Redemption Date")]
        public DateTimeOffset? RedemptionDate { get; set; }

        /// <summary>
        /// Gets or sets the reference identifier associated with the token.
        /// Note: depending on the application manager used when creating it,
        /// this property may be hashed or encrypted for security reasons.
        /// </summary>
        [Display(Name = "Reference Id")]
        public string? ReferenceId { get; set; }

        /// <summary>
        /// Gets or sets the status associated with the token.
        /// </summary>
        [Display(Name = "Status")]
        public string? Status { get; set; }

        /// <summary>
        /// Gets or sets the subject associated with the token.
        /// </summary>
        [Display(Name = "Subject")]
        public string? Subject { get; set; }

        /// <summary>
        /// Gets or sets the token type.
        /// </summary>
        [Display(Name = "Token Type")]
        public string? TokenType { get; set; }
    }
}

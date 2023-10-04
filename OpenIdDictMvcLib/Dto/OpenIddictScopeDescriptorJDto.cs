using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpenIdDictMvcLib.Dto
{
    public class OpenIddictScopeDescriptorJDto
    {

        /// <summary>
        /// Gets or sets the unique name associated with the scope.
        /// </summary>
        [Display(Name = "Scope Name")]
        public string? Name { get; set; }

        /// <summary>
        /// Gets or sets the display name associated with the scope.
        /// </summary>
        [Display(Name = "Display Name")]
        public string? DisplayName { get; set; }

        /// <summary>
        /// Gets or sets the description associated with the scope.
        /// </summary>
        [Display(Name = "Description")]
        public string? Description { get; set; }

        /// <summary>
        /// Gets the resources associated with the scope.
        /// </summary>
        [Display(Name = "Resources")]
        public string[]? Resources { get; set; }

        [Display(Name = "Display Names")]
        public List<DisplayNameDto>? DisplayNames { get; set; }

    }
}

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Localization;
using OpenIdDictMvcContext.Data;
using OpenIdDictMvcLib.Localizers;

namespace OpenIdDictMvcLib.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class ResendEmailConfirmationModel : PageModel
    {
        private readonly UserManager<OidcIdentityUser> _userManager;
        private readonly IEmailSender _emailSender;
        private readonly IStringLocalizer<IdentityLocalizerResource> _sharedLocalizer;
        public ResendEmailConfirmationModel(UserManager<OidcIdentityUser> userManager, IEmailSender emailSender, IStringLocalizer<IdentityLocalizerResource> SharedLocalizer)
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _sharedLocalizer = SharedLocalizer;
        }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        [BindProperty]
        public InputModel Input { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public class InputModel
        {
            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Required(ErrorMessage = "The Email field is required.")]
            [EmailAddress(ErrorMessage = "The Email field is not a valid e-mail address.")]
            [Display(Name = "Email")]
            public string Email { get; set; }
        }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null)
            {
                string s = _sharedLocalizer["Verification email sent. Please check your email."];
                ModelState.AddModelError(string.Empty, s);
                return Page();
            }

            var userId = await _userManager.GetUserIdAsync(user);
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
            var callbackUrl = Url.Page(
                "/Account/ConfirmEmail",
                pageHandler: null,
                values: new { userId = userId, code = code },
                protocol: Request.Scheme);
            string s1 = _sharedLocalizer["Confirm your email"];
            string s2 = _sharedLocalizer[$"Please confirm your account by < a href = '{HtmlEncoder.Default.Encode(callbackUrl)}' > clicking here </ a >."];
            await _emailSender.SendEmailAsync(
                Input.Email,
                s1,
                s2);
            string s3 = _sharedLocalizer["Verification email sent. Please check your email."];
            ModelState.AddModelError(string.Empty, s3);
            return Page();
        }
    }
}

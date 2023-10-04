// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using OpenIdDictMvcContext.Data;
using OpenIdDictMvcLib.Localizers;

namespace OpenIdDictMvcLib.Areas.Identity.Pages.Account
{
    public class LoginWithRecoveryCodeModel : PageModel
    {
        private readonly SignInManager<OidcIdentityUser> _signInManager;
        private readonly UserManager<OidcIdentityUser> _userManager;
        private readonly ILogger<LoginWithRecoveryCodeModel> _logger;
        private readonly IStringLocalizer<IdentityLocalizerResource> _sharedLocalizer;

        public LoginWithRecoveryCodeModel(
            SignInManager<OidcIdentityUser> signInManager,
            UserManager<OidcIdentityUser> userManager,
            ILogger<LoginWithRecoveryCodeModel> logger,
            IStringLocalizer<IdentityLocalizerResource> SharedLocalizer)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
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
        public string ReturnUrl { get; set; }

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
            [BindProperty]
            
            [Required(ErrorMessage = "The Recovery Code field is required.")]
            [DataType(DataType.Text)]
            [Display(Name = "Recovery Code")]
            public string RecoveryCode { get; set; }
        }

        public async Task<IActionResult> OnGetAsync(string returnUrl = null)
        {
            // Ensure the user has gone through the username & password screen first
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                string s = _sharedLocalizer[$"Unable to load two-factor authentication user."];
                throw new InvalidOperationException(s);
            }

            ReturnUrl = returnUrl;

            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                string s = _sharedLocalizer[$"Unable to load two-factor authentication user."];
                throw new InvalidOperationException(s);
            }

            var recoveryCode = Input.RecoveryCode.Replace(" ", string.Empty);

            var result = await _signInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);

            var userId = await _userManager.GetUserIdAsync(user);

            if (result.Succeeded)
            {
                string s1 = "User with ID '{UserId}' logged in with a recovery code.";
                _logger.LogInformation(s1, user.Id);
                return LocalRedirect(returnUrl ?? Url.Content("~/"));
            }
            if (result.IsLockedOut)
            {
                string s2 = "User account locked out.";
                _logger.LogWarning(s2);
                return RedirectToPage("./Lockout");
            }
            else
            {
                string s3 = "Invalid recovery code entered for user with ID '{UserId}' ";
                _logger.LogWarning(s3, user.Id);
                string s4 = _sharedLocalizer["Invalid recovery code entered."];
                ModelState.AddModelError(string.Empty, s4);
                return Page();
            }
        }
    }
}

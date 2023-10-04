// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using OpenIdDictMvcContext.Data;
using OpenIdDictMvcLib.Localizers;

namespace OpenIdDictMvcLib.Areas.Identity.Pages.Account.Manage
{
    public class ResetAuthenticatorModel : PageModel
    {
        private readonly UserManager<OidcIdentityUser> _userManager;
        private readonly SignInManager<OidcIdentityUser> _signInManager;
        private readonly ILogger<ResetAuthenticatorModel> _logger;
        private readonly IStringLocalizer<IdentityLocalizerResource> _sharedLocalizer;

        public ResetAuthenticatorModel(
            UserManager<OidcIdentityUser> userManager,
            SignInManager<OidcIdentityUser> signInManager,
            ILogger<ResetAuthenticatorModel> logger,
            IStringLocalizer<IdentityLocalizerResource> SharedLocalizer)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _sharedLocalizer = SharedLocalizer;
        }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        [TempData]
        public string StatusMessage { get; set; }

        public async Task<IActionResult> OnGet()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                string s = _sharedLocalizer["Unable to load user with ID"];
                return NotFound(s + $" '{_userManager.GetUserId(User)}'.");
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                string s = _sharedLocalizer["Unable to load user with ID"];
                return NotFound(s + $" '{_userManager.GetUserId(User)}'.");
            }

            await _userManager.SetTwoFactorEnabledAsync(user, false);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            var userId = await _userManager.GetUserIdAsync(user);
            string s1 = "User with ID '{UserId}' has reset their authentication app key.";
            _logger.LogInformation(s1, user.Id);

            await _signInManager.RefreshSignInAsync(user);
            StatusMessage = _sharedLocalizer["Your authenticator app key has been reset, you will need to configure your authenticator app using the new key."];

            return RedirectToPage("./EnableAuthenticator");
        }
    }
}

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
    public class Disable2faModel : PageModel
    {
        private readonly UserManager<OidcIdentityUser> _userManager;
        private readonly ILogger<Disable2faModel> _logger;
        private readonly IStringLocalizer<IdentityLocalizerResource> _sharedLocalizer;

        public Disable2faModel(
            UserManager<OidcIdentityUser> userManager,
            ILogger<Disable2faModel> logger, 
            IStringLocalizer<IdentityLocalizerResource> SharedLocalizer)
        {
            _userManager = userManager;
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

            if (!await _userManager.GetTwoFactorEnabledAsync(user))
            {
                string s1 = _sharedLocalizer[$"Cannot disable 2FA for user as it's not currently enabled."];
                throw new InvalidOperationException(s1);
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

            var disable2faResult = await _userManager.SetTwoFactorEnabledAsync(user, false);
            if (!disable2faResult.Succeeded)
            {
                string s1 = _sharedLocalizer[$"Unexpected error occurred disabling 2FA."];
                throw new InvalidOperationException(s1);
            }
            string s2 = "User with ID '{UserId}' has disabled 2fa.";
            _logger.LogInformation(s2, _userManager.GetUserId(User));
            StatusMessage = _sharedLocalizer["2fa has been disabled. You can reenable 2fa when you setup an authenticator app"];
            return RedirectToPage("./TwoFactorAuthentication");
        }
    }
}

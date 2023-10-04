// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using OpenIdDictMvcContext.Data;
using OpenIdDictMvcLib.Localizers;

namespace OpenIdDictMvcLib.Areas.Identity.Pages.Account.Manage
{
    public class DownloadPersonalDataModel : PageModel
    {
        private readonly UserManager<OidcIdentityUser> _userManager;
        private readonly ILogger<DownloadPersonalDataModel> _logger;
        private readonly IStringLocalizer<IdentityLocalizerResource> _sharedLocalizer;

        public DownloadPersonalDataModel(
            UserManager<OidcIdentityUser> userManager,
            ILogger<DownloadPersonalDataModel> logger,
            IStringLocalizer<IdentityLocalizerResource> SharedLocalizer)
        {
            _userManager = userManager;
            _logger = logger;
            _sharedLocalizer = SharedLocalizer;
        }

        public IActionResult OnGet()
        {
            return NotFound();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                string s = _sharedLocalizer["Unable to load user with ID"];
                return NotFound($" '{_userManager.GetUserId(User)}'.");
            }
            string s2 = "User with ID '{UserId}' asked for their personal data.";
            _logger.LogInformation(s2, _userManager.GetUserId(User));

            // Only include personal data for download
            var personalData = new Dictionary<string, string>();
            var personalDataProps = typeof(OidcIdentityUser).GetProperties().Where(
                            prop => Attribute.IsDefined(prop, typeof(PersonalDataAttribute)));
            foreach (var p in personalDataProps)
            {
                personalData.Add(p.Name, p.GetValue(user)?.ToString() ?? "null");
            }

            var logins = await _userManager.GetLoginsAsync(user);
            string s1 = _sharedLocalizer["external login provider key"];
            foreach (var l in logins)
            {
                personalData.Add($"{l.LoginProvider} " + s1, l.ProviderKey);
            }

            personalData.Add($"Authenticator Key", await _userManager.GetAuthenticatorKeyAsync(user));

            Response.Headers.Add("Content-Disposition", "attachment; filename=PersonalData.json");
            return new FileContentResult(JsonSerializer.SerializeToUtf8Bytes(personalData), "application/json");
        }
    }
}

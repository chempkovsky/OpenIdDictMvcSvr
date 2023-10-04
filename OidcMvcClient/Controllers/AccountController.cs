using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;

namespace OidcMvcClient.Controllers
{
    public class AccountController : Controller
    {
        [HttpGet]
        public IActionResult Login()
        {
            // defining  "RedirectUri" is important !!!
            var authProps = new AuthenticationProperties
            {
                RedirectUri = "/"
            };
            // do not use HttpContext.ChallengeAsync(...)-method call !!! It will not work
            return Challenge(authProps, OpenIdConnectDefaults.AuthenticationScheme);
        }
        [HttpGet("~/Account/Logout")]
        public async Task Logout()
        {
            await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
        }

        [HttpGet("~/Account/PostLogout")]
        public async Task<IActionResult> PostLogout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }
    }
}

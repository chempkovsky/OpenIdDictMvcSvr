using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;

namespace OidcStarterMvcClient.Controllers
{
    public class AccountController : Controller
    {
        [HttpGet]
        public IActionResult Login()
        {
            // defining  "RedirectUri" is important !!!
            var authProps = new AuthenticationProperties
            {
                // RedirectUri = "/Account/LoginEx"
                RedirectUri = "/"
            };
            // do not use HttpContext.ChallengeAsync(...)-method call !!! It will not work
            //return Challenge(authProps, new string[] { OpenIdSchemas.Schema01, OpenIdSchemas.Schema02 });
            return Challenge(authProps);
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

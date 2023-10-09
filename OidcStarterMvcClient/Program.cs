using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

#region begin Oidc added lines
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(
        options =>
        {
            options.LoginPath = "/Account/Login/";
            options.LogoutPath = "/Account/Logout";
            //
            // <ItemGroup>
            // ...
            // <PackageReference Include="Duende.AccessTokenManagement.OpenIdConnect" Version="2.0.3" />
            // ...
            // </ItemGroup>
            //
            //options.Events.OnSigningOut = async e =>
            //{
            //    await e.HttpContext.RevokeRefreshTokenAsync();
            //};
        }
)
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, o =>
{
        o.ClientId = "OidcStarterMvcClient";
        o.ClientSecret = "OidcStarterMvcClient_secrete";
        o.Authority = "https://localhost:7067/";
        o.ResponseType = OpenIdConnectResponseType.Code;
        o.ResponseMode = OpenIdConnectResponseMode.Query;
        o.UsePkce = true;
        o.SaveTokens = true;
        o.GetClaimsFromUserInfoEndpoint = true;
        o.SignedOutCallbackPath = "/signout-callback-oidc";
        o.SignedOutRedirectUri = "/Account/PostLogout";
        o.AuthenticationMethod = OpenIdConnectRedirectBehavior.RedirectGet;

        o.Scope.Clear();
        o.Scope.Add("openid");
        o.Scope.Add("profile");
        o.Scope.Add("GetCalimsScp");
        o.Scope.Add("GetRedirScp");
        // requests a refresh token
        o.Scope.Add("offline_access");
        o.TokenValidationParameters = new TokenValidationParameters
        {
            NameClaimType = "name",
            RoleClaimType = "role"
        };
        o.Events.OnTokenValidated = cntxt =>
        {
            if (cntxt.TokenEndpointResponse != null)
            {
                var scopes = cntxt.TokenEndpointResponse.Scope.Split(' ');
                if (scopes != null && (cntxt.Principal != null) && cntxt.Principal.Identity is ClaimsIdentity identity)
                {
                    foreach (var scope in scopes)
                    {
                        identity.AddClaim(new Claim("scope", scope));
                    }
                }
            }
            return Task.CompletedTask;
        };
        o.Events.OnRemoteFailure = cntxt =>
        {
            cntxt.Response.Redirect("/");
            cntxt.HandleResponse();
            return Task.CompletedTask;
        };
});
#endregion


// Add services to the container.
builder.Services.AddRazorPages();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

#region begin Oidc added lines
app.UseAuthentication();
#endregion
app.UseAuthorization();

#region begin Oidc added lines
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
#endregion

app.MapRazorPages();

app.Run();

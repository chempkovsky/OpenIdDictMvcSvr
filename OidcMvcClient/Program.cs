using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using OidcMvcClient;
using Microsoft.AspNetCore.Authentication;


// https://github.com/onelogin/openid-connect-dotnet-core-sample/blob/master/Startup.cs
var builder = WebApplication.CreateBuilder(args);


builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(
         options => { 
             options.LoginPath = "/Account/Login/";
             options.LogoutPath = "/Account/Logout";
             options.Events.OnSigningOut = async e =>
             {
                 await e.HttpContext.RevokeRefreshTokenAsync();
             };
         }
    )
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, o =>
    {
        o.ClientId = "OidcMvcClient";
        o.ClientSecret = "OidcMvcClient_secrete";
        o.Authority = "https://localhost:7067/";
        o.ResponseType = OpenIdConnectResponseType.Code; // OpenIdConnectResponseType.CodeIdTokenToken; // "code id_token token";
        o.ResponseMode = OpenIdConnectResponseMode.Query;
        o.UsePkce = true; // o.UsePkce = false; // o.UsePkce = true;
        o.SaveTokens = true;
        o.GetClaimsFromUserInfoEndpoint = true;
        o.SignedOutCallbackPath = "/signout-callback-oidc"; // "/signout-callback-oidc" is a default endpoint. Do not use "signout-oidc"
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

        //
        // At the server side
        // string?[]? auds = HttpContext.GetOpenIddictServerRequest().Audiences;
        //
        //o.Events.OnRedirectToIdentityProvider = cntxt =>
        //{
        //    cntxt.ProtocolMessage.SetParameter("audience", "xxx");
        //    cntxt.ProtocolMessage.SetParameter("audience", "yyy");
        //    cntxt.ProtocolMessage.SetParameter("audience", "zzz;yyy;xxx aaa bbb ccc");
        //    return Task.CompletedTask;
        //};
        // HttpContext.GetOpenIddictServerRequest().Audiences returns string[] {"zzz;yyy;xxx aaa bbb ccc"}
        //

        o.Events.OnTokenResponseReceived = cntxt =>
        {
            //var scopes = cntxt.TokenEndpointResponse.Scope.Split(' ');
            //if (scopes != null &&  (cntxt.Principal != null) && cntxt.Principal.Identity is ClaimsIdentity identity)
            //{
            //    foreach(var scope in scopes)
            //    {
            //        identity.AddClaim(new Claim("scope", scope));
            //    }
            //}
            return Task.CompletedTask;
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
        o.Events.OnRemoteFailure = cntxt => {
            cntxt.Response.Redirect("/");
            cntxt.HandleResponse();
            return Task.CompletedTask; 
        };
       // o.ForwardDefaultSelector = Selector.ForwardReferenceToken("introspection");
    })
    //.AddOAuth2Introspection(o =>
    //{
    //    o.ClientId = "OidcMvcClient";
    //    o.ClientSecret = "OidcMvcClient_secrete";
    //    o.Authority = "https://localhost:7067/";
    //    // o.IntrospectionEndpoint = "https://localhost:7067/"
    //});
    ;
//
// Demonstrating Proof of Possession (DPoP) is an application-level mechanism for sender-constraining OAuth
// [RFC6749] access and refresh tokens.
// https://datatracker.ietf.org/doc/html/rfc9449
//
builder.Services.AddOpenIdConnectAccessTokenManagement(o=>
    {
        o.ClientCredentialsScope = "openid profile offline_access GetCalimsScp GetRedirScp";
        o.ClientCredentialsResource = "OidcWebApiResource OidcWebApiIntrospectionResource";
     //   o.DPoPJsonWebKey = "jwk";
    });
//builder.Services.AddAccessTokenManagement(o =>
//{
//    o.Client.DefaultClient.Scope = "openid profile aaa ddd offline_access";
//});


//
//builder.Services.AddAuthorization(options => {
//    options.AddPolicy("MyPolicy", policy =>
//       policy.RequireAssertion(context =>
//       {
//           bool r = context.User.HasClaim(c => (c.Type == "BadgeId" || c.Type == "TemporaryBadgeId")
//           && c.Issuer == "https://microsoftsecurity");
//           return r;
//       }
//    ));
//});
//


// builder.Services.AddCors();

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

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapRazorPages();

app.Run();

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIdDictMvcLib.Confs;
using OpenIdDictMvcContext.Data;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);
// Add IConfiguration service
builder.Services.AddSingleton<IConfiguration>(builder.Configuration);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

builder.Services.AddDbContext<ApplicationDbContext>(options => {
    options.UseSqlServer(connectionString);
    // Register the entity sets needed by OpenIddict.
    // Note: use the generic overload if you need to replace the default OpenIddict entities.
    options.UseOpenIddict<OidcApplication, OidcAuthorization, OidcScope, OidcToken, string>();
});

builder.Services.AddDatabaseDeveloperPageExceptionFilter();

# region Prepare IdentityOptions
        var passwordOptions = new IdentityConf.PasswordConf();
        builder.Configuration.GetSection(IdentityConf.PasswordConf.SectionPath).Bind(passwordOptions);

        var lockoutOptions = new IdentityConf.LockoutConf();
        builder.Configuration.GetSection(IdentityConf.LockoutConf.SectionPath).Bind(lockoutOptions);

        var userOptions = new IdentityConf.UserConf();
        builder.Configuration.GetSection(IdentityConf.UserConf.SectionPath).Bind(userOptions);

        var claimsIdentityOptions = new IdentityConf.ClaimsIdentityConf();
        builder.Configuration.GetSection(IdentityConf.ClaimsIdentityConf.SectionPath).Bind(claimsIdentityOptions);

        var signInIdentityOptions = new IdentityConf.SignInConf();
        builder.Configuration.GetSection(IdentityConf.SignInConf.SectionPath).Bind(signInIdentityOptions);

        var analizeScopes = new IdentityConf.AnalizeScopesConf();
        builder.Configuration.GetSection(IdentityConf.AnalizeScopesConf.SectionPath).Bind(analizeScopes);
#endregion
#region Prepare OicdOptions
        var useReferenceTokens = new OidcConf.UseReferenceTokensConf();
        builder.Configuration.GetSection(OidcConf.UseReferenceTokensConf.SectionPath).Bind(useReferenceTokens);
        var tokenEncryption = new OidcConf.TokenEncryptionConf();
        builder.Configuration.GetSection(OidcConf.TokenEncryptionConf.SectionPath).Bind(tokenEncryption);
        var tokenLifetime = new OidcConf.TokenLifetimeConf();
        builder.Configuration.GetSection(OidcConf.TokenLifetimeConf.SectionPath).Bind(tokenLifetime);
#endregion


builder.Services.AddDefaultIdentity<OidcIdentityUser>(options => {
        // Password settings.
        options.Password.RequireDigit = passwordOptions.RequireDigit ?? true;
        options.Password.RequireLowercase = passwordOptions.RequireLowercase ?? true;
        options.Password.RequireNonAlphanumeric = passwordOptions.RequireNonAlphanumeric ?? true;
        options.Password.RequireUppercase = passwordOptions.RequireUppercase ?? true;
        options.Password.RequiredLength = passwordOptions.RequiredLength ?? 8;
        options.Password.RequiredUniqueChars = passwordOptions.RequiredUniqueChars ?? 1;

        // Lockout settings.
        options.Lockout.DefaultLockoutTimeSpan = lockoutOptions.DefaultLockoutTimeSpan ?? TimeSpan.FromMinutes(5);
        options.Lockout.MaxFailedAccessAttempts = lockoutOptions.MaxFailedAccessAttempts ?? 5;
        options.Lockout.AllowedForNewUsers = lockoutOptions.AllowedForNewUsers ?? true;

        // User settings.
        options.User.AllowedUserNameCharacters = userOptions.AllowedUserNameCharacters ?? "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
        options.User.RequireUniqueEmail = userOptions.RequireUniqueEmail ?? true;

        // ClaimsIdentity settings.
        options.ClaimsIdentity.RoleClaimType = claimsIdentityOptions.RoleClaimType ?? ClaimTypes.Role;
        options.ClaimsIdentity.UserNameClaimType = claimsIdentityOptions.UserNameClaimType ?? ClaimTypes.Name;
        options.ClaimsIdentity.UserIdClaimType = claimsIdentityOptions.UserIdClaimType ?? ClaimTypes.NameIdentifier;
        options.ClaimsIdentity.EmailClaimType = claimsIdentityOptions.EmailClaimType ?? ClaimTypes.Email;
        options.ClaimsIdentity.SecurityStampClaimType = claimsIdentityOptions.SecurityStampClaimType ?? "AspNet.Identity.SecurityStamp";

        // SignIn settings.
        options.SignIn.RequireConfirmedEmail = signInIdentityOptions.RequireConfirmedEmail ?? false;
        options.SignIn.RequireConfirmedPhoneNumber = signInIdentityOptions.RequireConfirmedPhoneNumber ?? false;
        options.SignIn.RequireConfirmedAccount = signInIdentityOptions.RequireConfirmedAccount ?? false;
    })
    .AddRoles<OidcIdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();


builder.Services.AddCors();
//string AllowedHosts = builder.Configuration["AllowedHosts"];
//builder.Services.AddCors(options =>
//{
//    options.AddDefaultPolicy(
//        builder =>
//        {
//            var allowedHosts = AllowedHosts;
//            foreach (var item in allowedHosts?.Split(';') ?? Enumerable.Empty<string>())
//            {
//                builder.WithOrigins(item);
//            }
//            //This is required for pre-flight request for CORS
//            builder.AllowAnyHeader();
//            builder.AllowAnyMethod();
//            builder.AllowCredentials();
//        });
//});



string OidcAllowedScopesRolePrefix = builder.Configuration["OidcAllowedScopes:RolePrefix"];
if(string.IsNullOrEmpty(OidcAllowedScopesRolePrefix)) OidcAllowedScopesRolePrefix = OidcAllowedScope.RolePrefix + "."; else OidcAllowedScopesRolePrefix += ".";
string OidcAllowedScopesClaimPrefix = builder.Configuration["OidcAllowedScopes:ClaimPrefix"];
if (string.IsNullOrEmpty(OidcAllowedScopesClaimPrefix)) OidcAllowedScopesClaimPrefix = OidcAllowedScope.ClaimPrefix + "."; else OidcAllowedScopesClaimPrefix += ".";

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Identity/Account/Login";


    if ((analizeScopes.AnalizeUserClaims.HasValue && analizeScopes.AnalizeUserClaims.Value) ||
        (analizeScopes.AnalizeRoleClaims.HasValue && analizeScopes.AnalizeRoleClaims.Value)) {
        options.Events.OnSigningIn = (ctx) =>
        {
            if (ctx.Principal != null)
            {
                List<Claim> lst = ctx.Principal.Claims.Where(c => c.Type == ClaimTypes.Role).ToList();
                foreach (var ñ in lst)
                {
                    if (ñ.Value != null)
                    {
                        if (ñ.Value.StartsWith(OidcAllowedScopesRolePrefix))
                        {
                            foreach (var i in ctx.Principal.Identities)
                            {
                                i.TryRemoveClaim(ñ);
                            }
                        }
                    }
                }
                lst = ctx.Principal.Claims.Where(c => c.Type.StartsWith(OidcAllowedScopesClaimPrefix)).ToList();
                foreach (var ñ in lst)
                {
                    foreach (var i in ctx.Principal.Identities)
                    {
                        i.TryRemoveClaim(ñ);
                    }
                }
            }
            return Task.CompletedTask;
        };
    }

});

// <snippet_EmailSender>
/*
builder.Services.AddTransient<IEmailSender, EmailSender>(i =>
                new EmailSender(
                    builder.Configuration["EmailSender:Host"],
                    builder.Configuration.GetValue<int>("EmailSender:Port"),
                    builder.Configuration.GetValue<bool>("EmailSender:EnableSSL"),
                    builder.Configuration["EmailSender:UserName"],
                    builder.Configuration["EmailSender:Password"]
                )
            );
*/
// </snippet_EmailSender>

// <snippet_LocalizationConfigurationServices>
// 1. this line has been added
builder.Services.AddLocalization(options => options.ResourcesPath = "Resources");
// </snippet_LocalizationConfigurationServices>

// <snippet_RequestLocalizationOptionsConfiguration>
// please read the article
// https://www.strathweb.com/2020/02/asp-net-core-mvc-3-x-addmvc-addmvccore-addcontrollers-and-other-bootstrapping-approaches/
builder.Services.AddControllersWithViews()
// 2. these 5 lines have been added
    .AddDataAnnotationsLocalization()
    .AddViewLocalization(LanguageViewLocationExpanderFormat.Suffix);
//.AddDataAnnotationsLocalization(options => {
//    options.DataAnnotationLocalizerProvider = (type, factory) =>
//        factory.Create(typeof(IdentityLocalizerResource));
//});
// </snippet_RequestLocalizationOptionsConfiguration>


// <snippet_AddOpenIddict>
builder.Services.AddOpenIddict()
        // Register the OpenIddict core components.
        .AddCore(options =>
        {
            // Configure OpenIddict to use the Entity Framework Core stores and models.
            // Note: call ReplaceDefaultEntities() to replace the default entities.
            options.UseEntityFrameworkCore()
                   .UseDbContext<ApplicationDbContext>()
                   .ReplaceDefaultEntities<OidcApplication, OidcAuthorization, OidcScope, OidcToken, string>();
        })
        .AddServer(options =>
        {
            int reftklf = 0;
            if (tokenLifetime.AccessTokenLifetimeFromMinutes.HasValue && tokenLifetime.AccessTokenLifetimeFromMinutes.Value > 0)
            {
                reftklf = tokenLifetime.AccessTokenLifetimeFromMinutes.Value + 1;
                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(tokenLifetime.AccessTokenLifetimeFromMinutes.Value));
            } else
            {
                reftklf = 61;
                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(60));
            }
            if (tokenLifetime.IdentityTokenLifetimeFromMinutes.HasValue && tokenLifetime.IdentityTokenLifetimeFromMinutes.Value > 0)
            {
                if (reftklf <= tokenLifetime.IdentityTokenLifetimeFromMinutes.Value)
                {
                    reftklf = tokenLifetime.IdentityTokenLifetimeFromMinutes.Value + 1;
                }
                options.SetIdentityTokenLifetime(TimeSpan.FromMinutes(tokenLifetime.IdentityTokenLifetimeFromMinutes.Value));
            }
            else
            {
                if(reftklf < 61)
                {
                    reftklf = 61;
                }
                options.SetIdentityTokenLifetime(TimeSpan.FromMinutes(60));
            }
            if (tokenLifetime.RefreshTokenLifetimeFromMinutes.HasValue && tokenLifetime.RefreshTokenLifetimeFromMinutes.Value > 0)
            {
                if(reftklf < tokenLifetime.RefreshTokenLifetimeFromMinutes.Value) {
                    reftklf = tokenLifetime.RefreshTokenLifetimeFromMinutes.Value;
                }
            }
            options.SetRefreshTokenLifetime(TimeSpan.FromMinutes(reftklf));

            // Enable the authorization, device, introspection,
            // logout, token, userinfo and verification endpoints.
            options.SetAuthorizationEndpointUris("connect/authorize")
                   .SetDeviceEndpointUris("connect/device")
                   .SetIntrospectionEndpointUris("connect/introspect")
                   .SetLogoutEndpointUris("connect/logout")
                   .SetTokenEndpointUris("connect/token")
                   .SetUserinfoEndpointUris("connect/userinfo")
                   .SetVerificationEndpointUris("connect/verify");

            // Note: this sample uses the code, device code, password and refresh token flows, but you
            // can enable the other flows if you need to support implicit or client credentials.
            // ==1==
            //   options
            //   .DisableScopeValidation();
            // ==2==
            // options.IgnoreScopePermissions();
            options
                .AllowAuthorizationCodeFlow()
                .AllowDeviceCodeFlow()
                .AllowRefreshTokenFlow()
                .AllowClientCredentialsFlow()
                .AllowPasswordFlow()
                .AllowHybridFlow()
                .AllowImplicitFlow();

            options.RegisterScopes(new string[] { "api", "bbb", "aaa" });


            //https://documentation.openiddict.com/configuration/encryption-and-signing-credentials.html
            //OpenIdDict uses two types of credentials to secure the token it issues.
            //1.Encryption credentials are used to ensure the content of tokens cannot be read by malicious parties
            if (!string.IsNullOrEmpty(builder.Configuration["Identity:Certificates:EncryptionCertificatePath"]))
            {
                var encryptionKeyBytes = File.ReadAllBytes(builder.Configuration["Identity:Certificates:EncryptionCertificatePath"]);
                X509Certificate2 encryptionKey = new(encryptionKeyBytes, builder.Configuration["Identity:EncryptionCertificateKey"],
                     X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.EphemeralKeySet);
                options.AddEncryptionCertificate(encryptionKey);
            }
            else
            {
                // byte[] keyForSymmetric256 = new byte[32];
                // var randomGen = RandomNumberGenerator.Create();
                // randomGen.GetBytes(keyForSymmetric256);
                // string base64Str =  Convert.ToBase64String(keyForSymmetric256);
                // var encryptionKey = new SymmetricSecurityKey(Convert.FromBase64String(base64Str));
                options.AddEncryptionKey(new SymmetricSecurityKey(Convert.FromBase64String("HKWKHaGFRyiUfgqKdAHOefFqzs44/U26bKPOw3Lk9yY="))); // <-- require KeySize = 256
            }

            //2.Signing credentials are used to protect against tampering
            if (!string.IsNullOrEmpty(builder.Configuration["Identity:Certificates:SigningCertificatePath"]))
            {
                var signingKeyBytes = File.ReadAllBytes(builder.Configuration["Identity:Certificates:SigningCertificatePath"]);
                X509Certificate2 signingKey = new(signingKeyBytes, builder.Configuration["Identity:SigningCertificateKey"],
                     X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.EphemeralKeySet);
                options
                .AddSigningCertificate(signingKey);
            }
            else
            {
                options.AddDevelopmentSigningCertificate();
            }

            // Force client applications to use Proof Key for Code Exchange (PKCE).
            options.RequireProofKeyForCodeExchange();


            //when integration with third-party APIs/resource servers is desired
            //options
            //    .DisableAccessTokenEncryption();

            // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
            options.UseAspNetCore()
                   .EnableStatusCodePagesIntegration()
                   .EnableAuthorizationEndpointPassthrough()
                   .EnableLogoutEndpointPassthrough()
                   .EnableTokenEndpointPassthrough()
                   .EnableUserinfoEndpointPassthrough()
                   .EnableVerificationEndpointPassthrough();

        // Note: if you don't want to specify a client_id when sending
        // a token or revocation request, uncomment the following line:
        //
        // options.AcceptAnonymousClients();

        // Note: if you want to process authorization and token requests
        // that specify non-registered scopes, uncomment the following line:
        //
        // options.DisableScopeValidation();


        // Note: if you don't want to use permissions, you can disable
        // permission enforcement by uncommenting the following lines:
        //
        // options.IgnoreEndpointPermissions()
        //        .IgnoreGrantTypePermissions()
        //        .IgnoreResponseTypePermissions()
        //        .IgnoreScopePermissions();

//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            if ((useReferenceTokens.RefreshTokens != null) && (useReferenceTokens.RefreshTokens.Value))
            {
                options.UseReferenceRefreshTokens();
            }
            if ((useReferenceTokens.AccessTokens != null) && (useReferenceTokens.AccessTokens.Value))
            {
                options.UseReferenceAccessTokens();
            }
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            // Note: when issuing access tokens used by third-party APIs
            // you don't own, you can disable access token encryption:
            //
            if ((tokenEncryption.DisableAccessTokenEncryption != null) && (tokenEncryption.DisableAccessTokenEncryption.Value))
            {
                options.DisableAccessTokenEncryption();
            }
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        })
        // Register the OpenIddict validation components.
        .AddValidation(options =>
        {
            // Import the configuration from the local OpenIddict server instance.
            options
                .UseLocalServer();
            // Register the ASP.NET Core host.
            options
                .UseAspNetCore();
        });

// </snippet_AddOpenIddict>

// <snippet_RequestLocalizationOptionsConfiguration>
builder.Services.Configure<RequestLocalizationOptions>(options =>
{
    var supportedCultures = new[] { "en", "ru" };
    options.SetDefaultCulture(supportedCultures[0])
        .AddSupportedCultures(supportedCultures)
        .AddSupportedUICultures(supportedCultures);
});
// </snippet_RequestLocalizationOptionsConfiguration>


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// <snippet_ConfigureLocalization>
IOptions<RequestLocalizationOptions>? localizationOptions = app.Services.GetService<IOptions<RequestLocalizationOptions>>();
if(localizationOptions != null)
  app.UseRequestLocalization(localizationOptions.Value);
// </snippet_ConfigureLocalization>

app.UseCors(x => x
    .AllowAnyMethod()
    .AllowAnyHeader()
    .SetIsOriginAllowed(origin => true) // allow any origin
    .AllowCredentials()); // allow credentials

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();

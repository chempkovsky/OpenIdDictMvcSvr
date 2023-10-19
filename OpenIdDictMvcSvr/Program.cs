using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIdDictMvcLib.Confs;
using OpenIdDictMvcContext.Data;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Microsoft.CodeAnalysis;
using System.Xml.Linq;
using System.Collections.Immutable;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Ocsp;

static X509Certificate2? GetCertificate(StoreLocation location, StoreName name, string thumbprint)
{
    using var store = new X509Store(name, location);
    store.Open(OpenFlags.ReadOnly);

    var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);

    return certificates.Count switch
    {
        0 => null,
        1 => certificates[0],
        _ => throw new InvalidOperationException("Multiple certificates with the same thumbprint were found."),
    };
}





static RSA GenerateRsaSecurityKey(int size)
{
    // By default, the default RSA implementation used by .NET Core relies on the newest Windows CNG APIs.
    // Unfortunately, when a new key is generated using the default RSA.Create() method, it is not bound
    // to the machine account, which may cause security exceptions when running Orchard on IIS using a
    // virtual application pool identity or without the profile loading feature enabled (off by default).
    // To ensure a RSA key can be generated flawlessly, it is manually created using the managed CNG APIs.
    // For more information, visit https://github.com/openiddict/openiddict-core/issues/204.
    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
        // Warning: ensure a null key name is specified to ensure the RSA key is not persisted by CNG.
        var key = CngKey.Create(CngAlgorithm.Rsa, keyName: null, new CngKeyCreationParameters
        {
            ExportPolicy = CngExportPolicies.AllowPlaintextExport,
            KeyCreationOptions = CngKeyCreationOptions.MachineKey,
            Parameters = { new CngProperty("Length", BitConverter.GetBytes(size), CngPropertyOptions.None) }
        });

        return new RSACng(key);
    }

    return RSA.Create(size);
}

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
// Add IConfiguration service
builder.Services.AddSingleton<IConfiguration>(builder.Configuration);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

bool UseMsSql = false;
if (builder.Configuration.GetValue<bool>("UseMsSql"))
{
    UseMsSql = true;
}

builder.Services.AddDbContext<ApplicationDbContext>(options => {
    if (UseMsSql)
    {
        options.UseSqlServer(connectionString);
    }
    else
    {
        options.UseSqlite(connectionString);
    }
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



builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Identity/Account/Login";
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
                   .SetRevocationEndpointUris("/connect/revoke")
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

            options.RegisterScopes(new string[] { "openid", "offline_access", "subject", "profile", "email", "roles", });

            //
            // https://documentation.openiddict.com/configuration/encryption-and-signing-credentials.html
            // OpenIdDict uses two types of credentials to secure the token it issues.
            // 1.Encryption credentials are used to ensure the content of tokens cannot be read by malicious parties
            //
            // 2. Note: when issuing access tokens used by third-party APIs
            //    you don't own, you can disable access token encryption:
            //
            if (tokenEncryption.DisableAccessTokenEncryption.HasValue && tokenEncryption.DisableAccessTokenEncryption.Value)
            {
                // we should add something to avoid throwing OpenIdDict exception
                options.AddEphemeralEncryptionKey();
                //when integration with third-party APIs/resource servers is desired
                options.DisableAccessTokenEncryption();

            }
            else
            {
                if (tokenEncryption.EncryptionCertificateStoreLocation.HasValue && 
                    tokenEncryption.EncryptionCertificateStoreName.HasValue &&
                    (!string.IsNullOrEmpty(tokenEncryption.EncryptionCertificateThumbprint)))
                {
                    var certificateE = GetCertificate(tokenEncryption.EncryptionCertificateStoreLocation.Value, tokenEncryption.EncryptionCertificateStoreName.Value, tokenEncryption.EncryptionCertificateThumbprint);
                    if (certificateE != null)
                    {
                        options.AddEncryptionKey(new X509SecurityKey(certificateE));
                    }
                }
                else
                {
                    options.AddEncryptionKey(new SymmetricSecurityKey(Convert.FromBase64String("HKWKHaGFRyiUfgqKdAHOefFqzs44/U26bKPOw3Lk9yY="))); // <-- require KeySize = 256
                    
                }
            }


            //2.Signing credentials are used to protect against tampering
            if (tokenEncryption.SigningCertificateStoreLocation.HasValue &&
                tokenEncryption.SigningCertificateStoreName.HasValue &&
                (!string.IsNullOrEmpty(tokenEncryption.SigningCertificateThumbprint)))
            {

                //var signingKeyBytes = File.ReadAllBytes("C:\\Development\\OpenIdDictMvcSvr\\OpenIdDictMvcSvr\\localhost-signing-certificate-self-signed.pfx");
                //X509Certificate2 signingKey = new(rawData: signingKeyBytes, password: "Qq?01011967");
                //,keyStorageFlags: X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.EphemeralKeySet);
                //options.AddSigningCertificate(signingKey);
                
                options.AddSigningCertificate(thumbprint: tokenEncryption.SigningCertificateThumbprint, 
                                              name: tokenEncryption.SigningCertificateStoreName.Value, 
                                              location: tokenEncryption.SigningCertificateStoreLocation.Value);
            }
            else
            {
                options.AddSigningKey(new SymmetricSecurityKey(Convert.FromBase64String("HKWKHaGFRyiUfgqKdAHOefFqzs44/U26bKPOw3Lk9yY="))); // <-- require KeySize = 256
            }


            // Force client applications to use Proof Key for Code Exchange (PKCE).
            options.RequireProofKeyForCodeExchange();


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
            //if ((tokenEncryption.DisableAccessTokenEncryption != null) && (tokenEncryption.DisableAccessTokenEncryption.Value))
            //{
            //    options.DisableAccessTokenEncryption();
            //}
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

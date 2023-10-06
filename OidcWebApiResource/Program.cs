using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using OidcWebApiResource.Helper;
using Microsoft.VisualBasic;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<IConfiguration>(builder.Configuration);

/*
    // 
    // Temporarily uncomment the block below to check if SigningKeys are returned
    //
     var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
        "https://localhost:7067/.well-known/openid-configuration",
        new OpenIdConnectConfigurationRetriever(),
        new HttpDocumentRetriever());
     var discoveryDocument = await configurationManager.GetConfigurationAsync();
     var signingKeys = discoveryDocument.SigningKeys;
*/


#region authentification
builder.Services.AddAuthentication(options => {
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, o => {
    o.SaveToken = true;
    o.Authority = "https://localhost:7067/";
    o.Audience = "OidcWebApiResource";
    o.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                                    "https://localhost:7067/.well-known/openid-configuration",
                                    new OpenIdConnectConfigurationRetriever(),
                                    new HttpDocumentRetriever());


    // o.MetadataAddress = "https://localhost:7067/.well-known/openid-configuration";

    o.TokenValidationParameters.ValidateIssuer = true;
    o.TokenValidationParameters.ValidateAudience = true; // <<<<<----- !!!!!!
    o.TokenValidationParameters.ValidateLifetime = true;
    o.TokenValidationParameters.ValidateTokenReplay = true;

    // o.TokenValidationParameters.TokenDecryptionKey = new SymmetricSecurityKey(Convert.FromBase64String("HKWKHaGFRyiUfgqKdAHOefFqzs44/U26bKPOw3Lk9yY="));
    
    o.TokenValidationParameters.ValidAudience = "OidcWebApiResource";
    o.TokenValidationParameters.RequireSignedTokens = true;
//    o.TokenValidationParameters.IssuerSigningKeys = signingKeys;
    o.TokenValidationParameters.IssuerSigningKey = null;
    o.TokenValidationParameters.ValidateIssuerSigningKey = true;

    if (o.Events == null) o.Events = new JwtBearerEvents();
    o.Events.OnTokenValidated = cntxt =>
    {
        if (cntxt.Principal != null)
        {
            if (cntxt.Principal.Claims != null)
            {
                var scp = cntxt.Principal.Claims.Where(c => c.Type == "scope").FirstOrDefault();
                if ((scp != null) && (!string.IsNullOrEmpty(scp.Value)))
                {
                    var scopes = scp.Value.Split(' ');
                    if (scopes != null && (cntxt.Principal != null) && cntxt.Principal.Identity is ClaimsIdentity identity)
                    {
                        foreach (var scope in scopes)
                        {
                            identity.AddClaim(new Claim("scope", scope));
                        }
                    }
                }
            }
        }


        return Task.CompletedTask;
    };
    o.Events.OnMessageReceived = cntxt =>
    {
        return Task.CompletedTask;
    };
    o.Events.OnAuthenticationFailed = cntxt =>
    {
        return Task.CompletedTask;
    };
});
builder.Services.AddHttpContextAccessor();
#endregion


builder.Services.AddAuthorization(options =>
        options.AddPolicy("HasGetCalimsScope",
        // claim value must be one of the allowed values
        policy => policy.RequireClaim(claimType: "scope", allowedValues: new string[] { "GetCalimsScp" }))
      );
builder.Services.AddAuthorization(options =>
        options.AddPolicy("HasGetRedirScope",
        // claim value must be one of the allowed values
        policy => policy.RequireClaim(claimType: "scope", allowedValues: new string[] { "GetRedirScp" }))
      );


// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

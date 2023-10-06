using IdentityModel.AspNetCore.OAuth2Introspection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

#region authentification
builder.Services.AddAuthentication(options => {
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddOAuth2Introspection(OAuth2IntrospectionDefaults.AuthenticationScheme, o => {
    o.Authority = "https://localhost:7067/";
    o.ClientId = "OidcWebApiIntrospectionResource";
    o.ClientSecret = "OidcWebApiIntrospectionResource_secret";
    //    o.IntrospectionEndpoint= "https://localhost:7067/connect/introspect";
    if (o.Events == null) o.Events = new OAuth2IntrospectionEvents();
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
    o.Events.OnAuthenticationFailed = cntxt =>
    {
        return Task.CompletedTask;
    };
});
;
builder.Services.AddHttpContextAccessor();
#endregion

builder.Services.AddAuthorization(options =>
        options.AddPolicy("HasGetCalimsScope",
        // claim value must be one of the allowed values
        policy => policy.RequireClaim(claimType: "scope", allowedValues: new string[] { "GetCalimsScp"}))
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

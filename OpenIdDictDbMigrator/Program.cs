// See https://aka.ms/new-console-template for more information
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIdDictMvcContext.Data;
using Microsoft.EntityFrameworkCore;
using OpenIdDictDbMigrator;

Console.WriteLine("OpenIdDict DbMigrator is getting ready to launch...");
Console.WriteLine();
Console.WriteLine("The Temp path is");
Console.WriteLine(Path.GetTempPath());
Console.WriteLine();
Console.WriteLine("The default connection string for MSSQL should look like this");
Console.WriteLine("  \"ConnectionStrings\":{");
Console.WriteLine($"     \"DefaultConnection\":\"Data Source = PETHOST\\PETSQL; Initial Catalog = OpenIdDictMvcSvr; Persist Security Info=True; User ID = sa; Password = password_here; TrustServerCertificate = True;\"");
Console.WriteLine("  }");

Console.WriteLine();
Console.WriteLine("The default connection string for SQLITE should look like this");
Console.WriteLine("  \"ConnectionStrings\":{");
Console.WriteLine($"     \"DefaultConnection\": \"Filename={Path.Combine(Path.GetTempPath(), "OpenIdDictMvcTestSvr.sqlite3")}\"");
Console.WriteLine("  }");


var builder = Host.CreateDefaultBuilder(args)
    .ConfigureAppConfiguration(c =>
        {
            c.AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);
        }
    ).ConfigureServices((context, services) => {
        IConfiguration Configuration = context.Configuration;
        var connectionString = Configuration.GetConnectionString("DefaultConnection");
        if (string.IsNullOrEmpty(connectionString))
        {
            Console.WriteLine();
            Console.WriteLine("Connection string is not defined.");
            Console.WriteLine("OpenIdDict DbMigrator stops...");
        }
        else
        {
            Console.WriteLine();
            Console.WriteLine("OpenIdDict DbMigrator is getting \"UseMsSql\"-section.");
            var useMsSql = Configuration.GetSection("UseMsSql").Get<bool>();
            if (useMsSql)
            {
                Console.WriteLine();
                Console.WriteLine("\"UseMsSql\"-section holds \"true\". OpenIdDict DbMigrator will work with MSSQL.");

                services.AddDbContext<ApplicationDbContext>(options =>
                {
                    options.UseSqlServer(connectionString);
                    // Register the entity sets needed by OpenIddict.
                    // Note: use the generic overload if you need to replace the default OpenIddict entities.
                    options.UseOpenIddict<OidcApplication, OidcAuthorization, OidcScope, OidcToken, string>();
                });
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine("\"UseMsSql\"-section holds \"false\". OpenIdDict DbMigrator will work with SQLITE.");
                services.AddDbContext<ApplicationDbContext>(options =>
                {
                    options.UseSqlite(connectionString);
                    // Register the entity sets needed by OpenIddict.
                    // Note: use the generic overload if you need to replace the default OpenIddict entities.
                    options.UseOpenIddict<OidcApplication, OidcAuthorization, OidcScope, OidcToken, string>();
                });
            }
            services.AddOpenIddict()
                // Register the OpenIddict core components.
                .AddCore(options =>
                {
                    // Configure OpenIddict to use the Entity Framework Core stores and models.
                    // Note: call ReplaceDefaultEntities() to replace the default entities.
                    options.UseEntityFrameworkCore()
                            .UseDbContext<ApplicationDbContext>()
                            .ReplaceDefaultEntities<OidcApplication, OidcAuthorization, OidcScope, OidcToken, string>();
                });
            services.AddDefaultIdentity<OidcIdentityUser>(options => { })
                .AddRoles<OidcIdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>();

        }
        services.AddHostedService<InteractiveService>();
        services.Configure<ConsoleLifetimeOptions>(options => options.SuppressStatusMessages = true);
    });

using var host = builder.UseConsoleLifetime().Build();
await host.RunAsync();
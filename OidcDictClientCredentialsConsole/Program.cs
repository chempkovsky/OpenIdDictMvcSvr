// See https://aka.ms/new-console-template for more information
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OidcDictClientCredentialsConsole;
using Microsoft.Extensions.Logging;
using OpenIddict.Client;


Console.WriteLine("OidcDictClientCredentialsConsole: Hello, World!");

var host = new HostBuilder()
    // Note: applications for which a single instance is preferred can reference
    // the Dapplo.Microsoft.Extensions.Hosting.AppServices package and call this
    // method to automatically close extra instances based on the specified identifier:
    //
    // .ConfigureSingleInstance(options => options.MutexId = "{C9E0D6B4-8142-4BC5-813B-12064CF4238C}")
    //
    .ConfigureLogging(options => options.AddDebug())
    .ConfigureServices(services =>
    {
        services.AddOpenIddict()

        // Register the OpenIddict client components.
        .AddClient(options =>
        {
            // Allow grant_type=client_credentials to be negotiated.
            options.AllowClientCredentialsFlow();

            // Disable token storage, which is not necessary for non-interactive flows like
            // grant_type=password, grant_type=client_credentials or grant_type=refresh_token.
            options.DisableTokenStorage();

            // Register the System.Net.Http integration and use the identity of the current
            // assembly as a more specific user agent, which can be useful when dealing with
            // providers that use the user agent as a way to throttle requests (e.g Reddit).
            options.UseSystemNetHttp()
                   .SetProductInformation(typeof(Program).Assembly);

            // Add a client registration matching the client application definition in the server project.
            options.AddRegistration(new OpenIddictClientRegistration
            {
                Issuer = new Uri("https://localhost:7067/", UriKind.Absolute),

                ClientId = "OidcDictClientCredentialsConsole",
                ClientSecret = "388D45FA-B36B-4988-BA59-B187D329C207"
            });
        });
        // Register the background service responsible for handling the console interactions.
        services.AddHostedService<InteractiveService>();

        // Prevent the console lifetime manager from writing status messages to the output stream.
        services.Configure<ConsoleLifetimeOptions>(options => options.SuppressStatusMessages = true);

    })
    .UseConsoleLifetime()
    .Build();

await host.RunAsync();

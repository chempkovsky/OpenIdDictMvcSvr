using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using OpenIddict.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Transactions;
using static OpenIddict.Client.OpenIddictClientModels;

namespace OidcDictClientCredentialsConsole
{
    internal class InteractiveService : BackgroundService
    {
        private readonly IHostApplicationLifetime _lifetime;
        private readonly OpenIddictClientService _service;
        public InteractiveService(
            IHostApplicationLifetime lifetime,
            OpenIddictClientService service)
        {
            _lifetime = lifetime;
            _service = service;
        }
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Wait for the host to confirm that the application has started.
            var source = new TaskCompletionSource<bool>();
            using (_lifetime.ApplicationStarted.Register(static state => ((TaskCompletionSource<bool>)state!).SetResult(true), source))
            {
                await source.Task;
            }


            try
            {
                ClientCredentialsAuthenticationResult rslt = await _service.AuthenticateWithClientCredentialsAsync(
                    new ClientCredentialsAuthenticationRequest()
                    {
                        CancellationToken = stoppingToken,
                        Issuer = new Uri("https://localhost:7067/", UriKind.Absolute),
                        Scopes = new() { "openid" }
                    }
                );
                if (rslt == null) {
                    Console.WriteLine("AuthenticateWithClientCredentialsAsync returns null");
                    return;
                };
                Console.WriteLine();
                Console.WriteLine("AccessToken: " + rslt.AccessToken);
                Console.WriteLine();
                Console.WriteLine("RefreshToken: " + rslt.IdentityToken);
                Console.WriteLine();
                Console.WriteLine("IdentityToken: " + rslt.RefreshToken);
                Console.WriteLine();
                Console.WriteLine("Close the app");
            } catch (Exception ex)
            {
                Exception? wex = ex;
                while (wex != null)
                {
                    Console.WriteLine(wex.Message);
                    wex = wex.InnerException;
                }
            }
        }

    }
}

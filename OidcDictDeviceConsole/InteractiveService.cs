using Microsoft.Extensions.Hosting;
using OpenIddict.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Abstractions.OpenIddictExceptions;
using Spectre.Console;

namespace OpenIdDictConsoleClient
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
                // Ask OpenIddict to send a device authorization request and write
                // the complete verification endpoint URI to the console output.
                var result = await _service.ChallengeUsingDeviceAsync(new()
                {
                    CancellationToken = stoppingToken
                });

                if (result.VerificationUriComplete is not null)
                {
                    AnsiConsole.MarkupLineInterpolated(
                        $"[yellow]Please visit [link]{result.VerificationUriComplete}[/] and confirm the displayed code is '{result.UserCode}' to complete the authentication demand.[/]");
                }

                else
                {
                    AnsiConsole.MarkupLineInterpolated(
                        $"[yellow]Please visit [link]{result.VerificationUri}[/] and enter '{result.UserCode}' to complete the authentication demand.[/]");
                }

                // Wait for the user to complete the demand on the other device.
                var principal = (await _service.AuthenticateWithDeviceAsync(new()
                {
                    DeviceCode = result.DeviceCode,
                    Interval = result.Interval,
                    Timeout = result.ExpiresIn < TimeSpan.FromMinutes(5) ? result.ExpiresIn : TimeSpan.FromMinutes(5)
                })).Principal;

                AnsiConsole.MarkupLine("[green]Authentication successful:[/]");

                var table = new Table()
                    .AddColumn(new TableColumn("Claim type").Centered())
                    .AddColumn(new TableColumn("Claim value type").Centered())
                    .AddColumn(new TableColumn("Claim value").Centered());

                foreach (var claim in principal.Claims)
                {
                    table.AddRow(
                        claim.Type.EscapeMarkup(),
                        claim.ValueType.EscapeMarkup(),
                        claim.Value.EscapeMarkup());
                }

                AnsiConsole.Write(table);
            }

            catch (OperationCanceledException ex1)
            {
                Exception? wex1 = ex1;
                StringBuilder sb1 = new StringBuilder();
                while (wex1 != null)
                {
                    sb1.AppendLine(wex1.Message);
                    wex1 = wex1.InnerException;
                }
                AnsiConsole.MarkupLine("[red]The authentication process was aborted.[/]");
                AnsiConsole.MarkupLine(sb1.ToString());
            }

            catch (ProtocolException exception) when (exception.Error is Errors.AccessDenied)
            {
                Exception? wex2 = exception;
                StringBuilder sb2 = new StringBuilder();
                while (wex2 != null)
                {
                    sb2.AppendLine(wex2.Message);
                    wex2 = wex2.InnerException;
                }
                AnsiConsole.MarkupLine("[yellow]The authorization was denied by the end user.[/]");
                AnsiConsole.MarkupLine(sb2.ToString());
            }

            catch (Exception ex)
            {
                Exception? wex = ex;
                StringBuilder sb = new StringBuilder();
                while (wex != null)
                {
                    sb.AppendLine(wex.Message);
                    wex = wex.InnerException;
                }
                AnsiConsole.MarkupLine("[red]An error occurred while trying to authenticate the user.[/]");
                AnsiConsole.MarkupLine(sb.ToString());
            }
        }

    }
}

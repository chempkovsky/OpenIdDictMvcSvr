using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace OpenIdDictMvcLib.Services
{
    //
    // EmailSenderConfigure was createrd according to the article
    // https://learn.microsoft.com/en-us/aspnet/core/fundamentals/configuration/?view=aspnetcore-7.0
    // ==1==
    // ---------------------------------------------------
    // in the program.cs file do the following
    //
    // var builder = WebApplication.CreateBuilder(args);
    // ...
    // builder.Services
    //   .AddEmailSenderConfig(builder.Configuration)
    // ---------------------------------------------------
    // ==2==
    // in the appsettings.json file add the following section: 
    // ---------------------------------------------------
    // "SMTP":  {
    //    "Host": "smtp.ethereal.email",
    //    "Port": 587,
    //    "UserName": "",
    //    "Password": "",
    //    "From": ""
    //  }
    // ---------------------------------------------------
    //
    public static class EmailSenderConfigure
    {
        public static IServiceCollection AddEmailSenderConfig(
                     this IServiceCollection services, IConfiguration configuration)
        {
            var smtpOptions = new EmailSenderSmtpOptions();
            configuration.GetSection(EmailSenderSmtpOptions.Smtp).Bind(smtpOptions);

            services.AddSingleton<EmailSenderSmtpOptions>(smtpOptions);
            services.AddTransient<IEmailSender, EmailSender>();
            return services;
        }
    }
}

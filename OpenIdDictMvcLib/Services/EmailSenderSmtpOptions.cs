
namespace OpenIdDictMvcLib.Services
{
    public class EmailSenderSmtpOptions
    {
        public const string Smtp = "SMTP";

        /// <summary>
        /// SMTP Host address
        /// </summary>
        public string Host { get; set; } = null!;

        /// <summary>
        /// SMTP Port to be used
        /// </summary>
        public string Port { get; set; } = null!;

        /// <summary>
        /// UserName for authentication
        /// </summary>
        public string UserName { get; set; } = null!;

        /// <summary>
        /// Password for authentication
        /// </summary>
        public string Password { get; set; } = null!;

        /// <summary>
        /// From for sending mail
        /// </summary>
        public string From { get; set; } = null!;

    }
}

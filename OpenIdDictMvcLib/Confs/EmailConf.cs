
namespace OpenIdDictMvcLib.Confs
{
    public class EmailConf
    {
        public class EmailSenderConf
        {
            public const string SectionPath = "Email:EmailSender";
            public bool RequireEmailSender { get; set; } = false;
            public string? Host { get; set; }
            public int? Port { get; set; }
            public bool? EnableSSL { get; set; }
            public string? UserName { get; set; }
            public string? Password { get; set; }

        }
    }
}

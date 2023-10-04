
namespace OpenIdDictMvcLib.Confs
{
    public class OidcConf
    {
        public class UseReferenceTokensConf
        {
            public const string SectionPath = "Oidc:UseReferenceTokens";
            /// <summary>
            /// Configures OpenIddict to use reference tokens, so that the refresh token payloads
            /// are stored in the database (only an identifier is returned to the client application).
            /// Enabling this option is useful when storing a very large number of claims in the tokens,
            /// but it is RECOMMENDED to enable column encryption in the database or use the ASP.NET Core
            /// Data Protection integration, that provides additional protection against token leakage.
            /// </summary>
            public bool? RefreshTokens { get; set; }
            public bool? AccessTokens { get; set; }
        }

        //
        // Note: when issuing access tokens used by third-party APIs
        // you don't own, you can disable access token encryption:
        //
        public class TokenEncryptionConf
        {
            public const string SectionPath = "Oidc:TokenEncryption";
            public bool? DisableAccessTokenEncryption { get; set; }
        }

        public class TokenLifetimeConf
        {
            public const string SectionPath = "Oidc:TokenLifetime";
            public int? AccessTokenLifetimeFromMinutes { get; set; }
            public int? IdentityTokenLifetimeFromMinutes { get; set; }
            public int? RefreshTokenLifetimeFromMinutes { get; set; }
        }
    }
}

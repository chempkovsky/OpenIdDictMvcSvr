
using Org.BouncyCastle.Asn1.X509;
using System.Security.Cryptography.X509Certificates;

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

        /*
         // Signature
          
             New-SelfSignedCertificate `
            -Subject "auth.rupbes.by" `
            -FriendlyName "auth.rupbes.by Signing Certificate" `
            -CertStoreLocation "cert:\LocalMachine\My" `
            -KeySpec Signature `
            -KeyUsage DigitalSignature `
            -KeyUsageProperty Sign `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") `
            -KeyExportPolicy NonExportable `
            -KeyAlgorithm RSA `
            -KeyLength 4096 `
            -HashAlgorithm SHA256 `
            -NotAfter(Get-Date).AddDays(825) `
            -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"


        // Encryption

             New-SelfSignedCertificate `
            -Subject "auth.rupbes.by" `
            -FriendlyName "auth.rupbes.by Signing Certificate" `
            -CertStoreLocation "cert:\LocalMachine\My" `
            -KeySpec Signature `
            -KeyUsage KeyEncipherment `
            -KeyUsageProperty Sign `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") `
            -KeyExportPolicy NonExportable `
            -KeyAlgorithm RSA `
            -KeyLength 4096 `
            -HashAlgorithm SHA256 `
            -NotAfter(Get-Date).AddDays(825) `
            -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"

        */


        //
        // Note: when issuing access tokens used by third-party APIs
        // you don't own, you can disable access token encryption:
        //
        public class TokenEncryptionConf
        {
            public const string SectionPath = "Oidc:TokenEncryption";
            public bool? DisableAccessTokenEncryption { get; set; }

            public StoreLocation? EncryptionCertificateStoreLocation { get; set; }
            public StoreName? EncryptionCertificateStoreName { get; set; }
            public string? EncryptionCertificateThumbprint { get; set; }

            public StoreLocation? SigningCertificateStoreLocation { get; set; }
            public StoreName? SigningCertificateStoreName { get; set; }
            public string? SigningCertificateThumbprint { get; set; }

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

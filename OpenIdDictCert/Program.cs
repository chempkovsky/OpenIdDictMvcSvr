using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;


void CreteCertAndCertRequest(X509KeyUsageFlags Flags,
    string DomainComponent, string CommonName, string StateOrProvinceName, string DerFileName, string PemFileName, string FriendlyName, string PfxFileName, string PassWord)
{
    using var algorithm = RSA.Create(keySizeInBits: 2048);
    X500DistinguishedNameBuilder nmbldr = new X500DistinguishedNameBuilder();
    nmbldr.AddDomainComponent(DomainComponent);
    nmbldr.AddCommonName(CommonName);
    nmbldr.AddStateOrProvinceName(StateOrProvinceName);
    var subject = nmbldr.Build();
    var request = new CertificateRequest(subject, algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    request.CertificateExtensions.Add(new X509KeyUsageExtension(Flags, critical: true));

    File.WriteAllBytes(DerFileName, request.CreateSigningRequest());
    Console.WriteLine(DerFileName + " has been created. It is Request for Signing");

    StringBuilder builder = new StringBuilder();
    builder.AppendLine("-----BEGIN CERTIFICATE REQUEST-----");
    string base64 = Convert.ToBase64String(request.CreateSigningRequest());
    int offset = 0;
    const int LineLength = 64;
    while (offset < base64.Length)
    {
        int lineEnd = Math.Min(offset + LineLength, base64.Length);
        builder.AppendLine(base64.Substring(offset, lineEnd - offset));
        offset = lineEnd;
    }
    builder.AppendLine("-----END CERTIFICATE REQUEST-----");
    File.WriteAllText(PemFileName, builder.ToString());

    var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(2));
    //
    // next line is for Windows only
    // certificate.FriendlyName = FriendlyName;
    //

    File.WriteAllBytes(PfxFileName, certificate.Export(X509ContentType.Pfx, PassWord));
    Console.WriteLine(PfxFileName + " has been created");
}

//
// https://docs.orchardcore.net/fr/latest/docs/reference/modules/OpenId/
//

    CreteCertAndCertRequest(X509KeyUsageFlags.KeyEncipherment,
    "auth.rupbes.by", "auth.rupbes.by Encryption Certificate", "BY",
    "auth-encryption-certificate-request.der", "auth-encryption-certificate-request.pem", 
    "Self Signed Encryption Certificate for auth.rupbes.by",
    "auth-encryption-certificate-self-signed.pfx", "Qq?01011967");

    CreteCertAndCertRequest(X509KeyUsageFlags.DigitalSignature,
    "auth.rupbes.by", "auth.rupbes.by Signing Certificate", "BY",
    "auth-signing-certificate-request.der", "auth-signing-certificate-request.pem", 
    "Self Signed Signing Certificate for auth.rupbes.by",
    "auth-signing-certificate-self-signed.pfx", "Qq?01011967");

/*
CreteCertAndCertRequest(X509KeyUsageFlags.KeyEncipherment,
                        "authclt.rupbes.by", "rupbes.by Encryption Certificate", "BY",
                        "authclt-encryption-certificate-request.der", "authclt-encryption-certificate-request.pem", "Self Signed Encryption Certificate for authclt.rupbes.by",
                        "authclt-encryption-certificate-self-signed.pfx", "Qq?01011967");

CreteCertAndCertRequest(X509KeyUsageFlags.DigitalSignature,
                        "authclt.rupbes.by", "rupbes.by Signing Certificate", "BY",
                        "authclt-signing-certificate-request.der", "authclt-signing-certificate-request.pem", "Self Signed Signing Certificate for authclt.rupbes.by",
                        "authclt-signing-certificate-self-signed.pfx", "Qq?01011967");


CreteCertAndCertRequest(X509KeyUsageFlags.KeyEncipherment,
                        "corp.rupbes.by", "rupbes.by Encryption Certificate", "BY",
                        "corp-encryption-certificate-request.der", "corp-encryption-certificate-request.pem", "Self Signed Encryption Certificate for corp.rupbes.by",
                        "corp-encryption-certificate-self-signed.pfx", "Qq?01011967");

CreteCertAndCertRequest(X509KeyUsageFlags.DigitalSignature,
                        "corp.rupbes.by", "rupbes.by Signing Certificate", "BY",
                        "corp-signing-certificate-request.der", "corp-signing-certificate-request.pem", "Self Signed Signing Certificate for corp.rupbes.by",
                        "corp-signing-certificate-self-signed.pfx", "Qq?01011967");
*/
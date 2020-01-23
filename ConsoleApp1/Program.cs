using System;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== CurveBall ===");
            
            var parameters = ECNamedCurveTable.GetByName("prime256v1");
            
            var publicKey = parameters.Curve.DecodePoint(new byte[]{});
            var privateKey = parameters.Curve.FromBigInteger(BigInteger.Two);
            var generator = publicKey.Multiply(privateKey.Invert().ToBigInteger());
            

        }
    }
}
using System;
using System.Security.Cryptography;
using System.Text;

namespace TlsDecryptionEngine.Kdf;

public class Tls12KeyDerivation
{
    public static byte[] PRF(byte[] secret, string label, byte[] seed, int outputLength, HashAlgorithmName hashAlgorithm)
    {
        byte[] labelBytes = Encoding.ASCII.GetBytes(label);
        byte[] msg = new byte[labelBytes.Length + seed.Length];
        Buffer.BlockCopy(labelBytes, 0, msg, 0, labelBytes.Length);
        Buffer.BlockCopy(seed, 0, msg, labelBytes.Length, seed.Length);

        return P_Hash(secret, msg, outputLength, hashAlgorithm);
    }

    private static byte[] P_Hash(byte[] secret, byte[] seed, int outputLength, HashAlgorithmName hashAlgorithm)
    {
        using HMAC hmac = HMAC.Create($"HMAC{hashAlgorithm.Name}")!;
        hmac.Key = secret;

        byte[] result = new byte[outputLength];
        int generated = 0;

        byte[] a = seed;

        while (generated < outputLength)
        {
            a = hmac.ComputeHash(a); // A(i) = HMAC_hash(secret, A(i-1))
            
            byte[] aAndSeed = new byte[a.Length + seed.Length];
            Buffer.BlockCopy(a, 0, aAndSeed, 0, a.Length);
            Buffer.BlockCopy(seed, 0, aAndSeed, a.Length, seed.Length);

            byte[] h = hmac.ComputeHash(aAndSeed);

            int copyLength = Math.Min(h.Length, outputLength - generated);
            Buffer.BlockCopy(h, 0, result, generated, copyLength);
            generated += copyLength;
        }

        return result;
    }
}

using System;
using System.Security.Cryptography;
using System.Buffers.Binary;

namespace TlsDecryptionEngine.Kdf;

public static class Tls13KeyDerivation
{
    // HKDF-Extract(salt, IKM) -> PRK
    public static byte[] HKDFExtract(byte[] salt, byte[] ikm, HashAlgorithmName hashAlgorithm)
    {
        return HKDF.Extract(hashAlgorithm, ikm, salt);
    }

    // HKDF-Expand(PRK, info, L) -> OKM
    public static byte[] HKDFExpand(byte[] prk, byte[] info, int length, HashAlgorithmName hashAlgorithm)
    {
        return HKDF.Expand(hashAlgorithm, prk, length, info);
    }

    public static byte[] HKDFExpandLabel(byte[] secret, string label, byte[] context, int length, HashAlgorithmName hashAlgorithm)
    {
        // HkdfLabel = uint16 length, uint8 labelLen, opaque label<7..255>, uint8 contextLen, opaque context<0..255>
        byte[] labelBytes = System.Text.Encoding.ASCII.GetBytes("tls13 " + label);
        
        int hkdfLabelLen = 2 + 1 + labelBytes.Length + 1 + context.Length;
        byte[] hkdfLabel = new byte[hkdfLabelLen];

        BinaryPrimitives.WriteUInt16BigEndian(hkdfLabel.AsSpan(0, 2), (ushort)length);
        hkdfLabel[2] = (byte)labelBytes.Length;
        Buffer.BlockCopy(labelBytes, 0, hkdfLabel, 3, labelBytes.Length);
        
        int contextOffset = 3 + labelBytes.Length;
        hkdfLabel[contextOffset] = (byte)context.Length;
        Buffer.BlockCopy(context, 0, hkdfLabel, contextOffset + 1, context.Length);

        return HKDFExpand(secret, hkdfLabel, length, hashAlgorithm);
    }
}

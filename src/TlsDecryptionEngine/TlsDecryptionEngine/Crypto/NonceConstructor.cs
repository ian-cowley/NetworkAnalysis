using System;
using System.Buffers.Binary;

namespace TlsDecryptionEngine.Crypto;

public class NonceConstructor
{
    private ulong _sequenceNumber = 0;
    private readonly byte[] _staticIv;
    private readonly bool _isTls13;

    public NonceConstructor(byte[] staticIv, bool isTls13)
    {
        _staticIv = staticIv;
        _isTls13 = isTls13;
    }

    public byte[] GetNextNonce(byte[]? explicitNonce = null)
    {
        byte[] nonce = new byte[_staticIv.Length];

        if (_isTls13)
        {
            // TLS 1.3: XOR static IV with sequence number padded to left with zeros
            Buffer.BlockCopy(_staticIv, 0, nonce, 0, _staticIv.Length);
            
            byte[] seqBytes = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(seqBytes, _sequenceNumber);

            // Sequence number is XORed with the bottom 8 bytes of the IV
            int offset = _staticIv.Length - 8;
            for (int i = 0; i < 8; i++)
            {
                nonce[offset + i] ^= seqBytes[i];
            }
        }
        else
        {
            // TLS 1.2 GCM usually uses 4 bytes of static implicit salt from key block + 8 bytes explicit nonce
            if (explicitNonce != null && explicitNonce.Length == 8)
            {
                Buffer.BlockCopy(_staticIv, 0, nonce, 0, 4);
                Buffer.BlockCopy(explicitNonce, 0, nonce, 4, 8);
            }
            else
            {
                // Fallback / Chacha20 logic for 1.2
                Buffer.BlockCopy(_staticIv, 0, nonce, 0, _staticIv.Length);
                
                byte[] seqBytes = new byte[8];
                BinaryPrimitives.WriteUInt64BigEndian(seqBytes, _sequenceNumber);
                
                int offset = _staticIv.Length - 8;
                for (int i = 0; i < 8; i++)
                {
                    nonce[offset + i] ^= seqBytes[i];
                }
            }
        }

        _sequenceNumber++;
        return nonce;
    }
}

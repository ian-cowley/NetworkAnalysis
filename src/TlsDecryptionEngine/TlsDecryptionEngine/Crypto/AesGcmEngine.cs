using System;
using System.Security.Cryptography;

namespace TlsDecryptionEngine.Crypto;

public class AesGcmEngine : ICipherEngine
{
    private readonly AesGcm _aes;

    public AesGcmEngine(byte[] key)
    {
        _aes = new AesGcm(key, tagSizeInBytes: 16);
    }

    public byte[] Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] associatedData)
    {
        byte[] plaintext = new byte[ciphertext.Length];
        _aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        return plaintext;
    }

    public void Dispose()
    {
        _aes.Dispose();
    }
}

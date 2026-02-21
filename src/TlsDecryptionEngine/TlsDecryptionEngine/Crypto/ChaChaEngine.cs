using System;
using System.Security.Cryptography;

namespace TlsDecryptionEngine.Crypto;

public class ChaChaEngine : ICipherEngine
{
    private readonly ChaCha20Poly1305 _chacha;

    public ChaChaEngine(byte[] key)
    {
        _chacha = new ChaCha20Poly1305(key);
    }

    public byte[] Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] associatedData)
    {
        byte[] plaintext = new byte[ciphertext.Length];
        _chacha.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        return plaintext;
    }

    public void Dispose()
    {
        _chacha.Dispose();
    }
}

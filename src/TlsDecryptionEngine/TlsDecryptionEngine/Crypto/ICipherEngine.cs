using System;

namespace TlsDecryptionEngine.Crypto;

public interface ICipherEngine : IDisposable
{
    byte[] Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] associatedData);
}

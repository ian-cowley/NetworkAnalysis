using System;
using System.Buffers.Binary;
using TlsDecryptionEngine.Tls;

namespace TlsDecryptionEngine.Crypto;

public class TlsRecordDecryptor
{
    private readonly ICipherEngine _engine;
    private readonly NonceConstructor _nonceConstructor;

    public TlsRecordDecryptor(ICipherEngine engine, NonceConstructor nonceConstructor)
    {
        _engine = engine;
        _nonceConstructor = nonceConstructor;
    }

    public byte[]? DecryptRecord(TlsRecord record)
    {
        if (record.ContentType != TlsContentType.ApplicationData)
        {
            return null; // or throw depending on how we want to handle non-app data after handshake
        }

        byte[] payload = record.Payload;

        // Determine explicit nonce vs ciphertext based on ciphersuite rules outside this class, 
        // but let's assume TLS 1.3 implicit for simplicity here as an example wrapper
        
        // Example TLS 1.3 GCM decryption structure:
        // Plaintext length = payload.Length - 16 (tag)
        if (payload.Length < 16) return null;

        int ciphertextLen = payload.Length - 16;
        byte[] ciphertext = new byte[ciphertextLen];
        byte[] tag = new byte[16];

        Buffer.BlockCopy(payload, 0, ciphertext, 0, ciphertextLen);
        Buffer.BlockCopy(payload, ciphertextLen, tag, 0, 16);

        byte[] nonce = _nonceConstructor.GetNextNonce();
        
        // Associated Data (AAD) for TLS 1.3:
        // Opaque_type (23) || Legacy_version (0x0303) || Length (uint16)
        byte[] aad = new byte[5];
        aad[0] = (byte)TlsContentType.ApplicationData;
        aad[1] = 0x03; // Protocol Version Major
        aad[2] = 0x03; // Protocol Version Minor
        BinaryPrimitives.WriteUInt16BigEndian(aad.AsSpan(3), (ushort)payload.Length);

        try
        {
            byte[] plaintext = _engine.Decrypt(nonce, ciphertext, tag, aad);
            // In TLS 1.3, plaintext ends with the real ContentType byte + optional padding
            return StripTls13Padding(plaintext);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Decryption failed: {ex.Message}");
            return null;
        }
    }

    private byte[] StripTls13Padding(byte[] plaintext)
    {
        int realLen = plaintext.Length;
        while (realLen > 0 && plaintext[realLen - 1] == 0)
        {
            realLen--;
        }
        
        if (realLen == 0) return Array.Empty<byte>();

        // last non-zero byte is the real content type
        byte innerType = plaintext[realLen - 1];
        
        byte[] actualPlaintext = new byte[realLen - 1];
        Buffer.BlockCopy(plaintext, 0, actualPlaintext, 0, realLen - 1);
        return actualPlaintext;
    }
}

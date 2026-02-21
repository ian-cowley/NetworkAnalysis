using System;
using System.Buffers.Binary;

namespace TlsDecryptionEngine.Tls;

public enum TlsHandshakeType : byte
{
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EncryptedExtensions = 8,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20
}

public class TlsHandshakeMessage
{
    public TlsHandshakeType HandshakeType { get; set; }
    public uint Length { get; set; }
    public byte[] Payload { get; set; } = Array.Empty<byte>();

    public static TlsHandshakeMessage? Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4) return null;

        var type = (TlsHandshakeType)data[0];
        
        // 24-bit length
        uint length = ((uint)data[1] << 16) | ((uint)data[2] << 8) | data[3];

        if (data.Length < 4 + length) return null;

        return new TlsHandshakeMessage
        {
            HandshakeType = type,
            Length = length,
            Payload = data.Slice(4, (int)length).ToArray()
        };
    }
}

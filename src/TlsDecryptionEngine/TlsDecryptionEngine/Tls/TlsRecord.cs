using System;

namespace TlsDecryptionEngine.Tls;

public enum TlsContentType : byte
{
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Heartbeat = 24
}

public class TlsRecord
{
    public TlsContentType ContentType { get; set; }
    public ushort Version { get; set; }
    public ushort Length { get; set; }
    public byte[] Payload { get; set; } = Array.Empty<byte>();
}

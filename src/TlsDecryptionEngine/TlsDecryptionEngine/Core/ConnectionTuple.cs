namespace TlsDecryptionEngine.Core;

public readonly record struct ConnectionTuple(string SourceIp, ushort SourcePort, string DestIp, ushort DestPort)
{
    public ConnectionTuple GetReversed() => new(DestIp, DestPort, SourceIp, SourcePort);
}

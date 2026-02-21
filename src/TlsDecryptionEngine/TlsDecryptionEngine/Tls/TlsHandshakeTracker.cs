using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace TlsDecryptionEngine.Tls;

public class TlsHandshakeTracker
{
    public byte[]? ClientRandom { get; private set; }
    public byte[]? ServerRandom { get; private set; }
    public ushort? SelectedCipherSuite { get; private set; }

    public void ProcessRecord(TlsRecord record)
    {
        if (record.ContentType != TlsContentType.Handshake) return;

        int offset = 0;
        var payloadSpan = record.Payload.AsSpan();

        while (offset < payloadSpan.Length)
        {
            var handshake = TlsHandshakeMessage.Parse(payloadSpan.Slice(offset));
            if (handshake == null) break;

            ProcessHandshake(handshake);
            offset += 4 + (int)handshake.Length;
        }
    }

    private void ProcessHandshake(TlsHandshakeMessage handshake)
    {
        if (handshake.HandshakeType == TlsHandshakeType.ClientHello)
        {
            ParseClientHello(handshake.Payload);
        }
        else if (handshake.HandshakeType == TlsHandshakeType.ServerHello)
        {
            ParseServerHello(handshake.Payload);
        }
    }

    private void ParseClientHello(ReadOnlySpan<byte> payload)
    {
        // ProtocolVersion (2) + Random (32)
        if (payload.Length < 34) return;
        ClientRandom = payload.Slice(2, 32).ToArray();
    }

    private void ParseServerHello(ReadOnlySpan<byte> payload)
    {
        // ProtocolVersion (2) + Random (32) + SessionIdLength (1)
        if (payload.Length < 35) return;
        ServerRandom = payload.Slice(2, 32).ToArray();

        int sessionIdLength = payload[34];
        int cipherSuiteOffset = 35 + sessionIdLength;
        
        if (payload.Length >= cipherSuiteOffset + 2)
        {
            SelectedCipherSuite = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(cipherSuiteOffset, 2));
        }
    }
}

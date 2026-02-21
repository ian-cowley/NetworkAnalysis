using System.Collections.Generic;

namespace TlsDecryptionEngine.Kdf;

public class KeyLogSecrets
{
    public byte[]? ClientRandom { get; set; }
    
    // TLS 1.2
    public byte[]? MasterSecret { get; set; }

    // TLS 1.3
    public byte[]? ClientHandshakeTrafficSecret { get; set; }
    public byte[]? ServerHandshakeTrafficSecret { get; set; }
    public byte[]? ClientTrafficSecret0 { get; set; }
    public byte[]? ServerTrafficSecret0 { get; set; }
    public byte[]? ExporterSecret { get; set; }
}

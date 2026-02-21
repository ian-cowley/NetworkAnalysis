using System;
using System.Collections.Generic;
using System.IO;

namespace TlsDecryptionEngine.Kdf;

public class KeyLogFileParser
{
    // Keyed by the 32-byte Client Random (hex string uppercase)
    private readonly Dictionary<string, KeyLogSecrets> _secretsByClientRandom = new();

    public IReadOnlyDictionary<string, KeyLogSecrets> Secrets => _secretsByClientRandom;

    public void Parse(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("SSLKEYLOGFILE not found", filePath);

        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(fs);

        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                continue;

            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 3) continue;

            string label = parts[0];
            string clientRandomHex = parts[1].ToUpperInvariant();
            string secretHex = parts[2];

            if (!_secretsByClientRandom.TryGetValue(clientRandomHex, out var secrets))
            {
                secrets = new KeyLogSecrets { ClientRandom = ConvertHexStringToByteArray(clientRandomHex) };
                _secretsByClientRandom[clientRandomHex] = secrets;
            }

            var secretBytes = ConvertHexStringToByteArray(secretHex);

            switch (label)
            {
                case "CLIENT_RANDOM":
                    secrets.MasterSecret = secretBytes;
                    break;
                case "CLIENT_HANDSHAKE_TRAFFIC_SECRET":
                    secrets.ClientHandshakeTrafficSecret = secretBytes;
                    break;
                case "SERVER_HANDSHAKE_TRAFFIC_SECRET":
                    secrets.ServerHandshakeTrafficSecret = secretBytes;
                    break;
                case "CLIENT_TRAFFIC_SECRET_0":
                    secrets.ClientTrafficSecret0 = secretBytes;
                    break;
                case "SERVER_TRAFFIC_SECRET_0":
                    secrets.ServerTrafficSecret0 = secretBytes;
                    break;
                case "EXPORTER_SECRET":
                    secrets.ExporterSecret = secretBytes;
                    break;
            }
        }
    }

    public KeyLogSecrets? GetSecrets(byte[] clientRandom)
    {
        if (clientRandom == null) return null;
        string hex = BitConverter.ToString(clientRandom).Replace("-", "").ToUpperInvariant();
        _secretsByClientRandom.TryGetValue(hex, out var secrets);
        return secrets;
    }

    public static byte[] ConvertHexStringToByteArray(string hex)
    {
        if (hex.Length % 2 != 0)
            throw new ArgumentException("Hex string must have an even length");

        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < hex.Length; i += 2)
        {
            bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        }
        return bytes;
    }
}

using System;
using System.IO;
using System.Collections.Generic;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using TlsDecryptionEngine.Core;
using TlsDecryptionEngine.Kdf;
using System.Security.Cryptography;

namespace TlsDecryptionEngine.Benchmarks;

[ShortRunJob]
[MemoryDiagnoser]
public class PerformanceBenchmarks
{
    private byte[] _payload = Array.Empty<byte>();
    private byte[] _ikm = Array.Empty<byte>();
    private byte[] _salt = Array.Empty<byte>();

    [GlobalSetup]
    public void Setup()
    {
        _payload = new byte[1500]; // typical ethernet MTU minus headers
        new Random(42).NextBytes(_payload);

        _ikm = new byte[32];
        _salt = new byte[32];
        new Random(42).NextBytes(_ikm);
        new Random(43).NextBytes(_salt);
    }

    [Benchmark(Description = "TCP Stream Reassembly (Optimized MemoryStream)")]
    public void TcpReassemblyOptimized()
    {
        var stream = new TcpDirectionStream();
        uint seq = 100;

        for (int i = 0; i < 1000; i++) // simulate 1 MB flow
        {
            stream.AddSegment(seq, _payload);
            seq += (uint)_payload.Length;
        }

        var result = stream.ReassembledData;
    }

    [Benchmark(Description = "TLS 1.3 HKDF Extraction (AES-NI)")]
    public void HkdfExtraction()
    {
        for (int i = 0; i < 100; i++)
        {
            var prk = Tls13KeyDerivation.HKDFExtract(_salt, _ikm, HashAlgorithmName.SHA256);
        }
    }
}

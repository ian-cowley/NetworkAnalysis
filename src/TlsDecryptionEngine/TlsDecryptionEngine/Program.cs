using System;
using TlsDecryptionEngine.Core;
using TlsDecryptionEngine.Kdf;

namespace TlsDecryptionEngine;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("=== TLS Decryption Engine ===");
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: TlsDecryptionEngine <pcap_file> <sslkeylogfile>");
            return;
        }

        string pcapFile = args[0];
        string keyLogFile = args[1];

        // 1. Ingest KeyLog File
        Console.WriteLine($"[1] Parsing Keylog file: {keyLogFile}");
        var keyLogParser = new KeyLogFileParser();
        try
        {
            keyLogParser.Parse(keyLogFile);
            Console.WriteLine($"    -> Extracted {keyLogParser.Secrets.Count} Client Random secrets.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading KeyLog File: {ex.Message}");
            return;
        }

        // 2. Setup PCAP Reader & Reassembler
        var reassembler = new TcpStreamReassembler();
        var readerService = new PcapReaderService(reassembler);

        Console.WriteLine($"[2] Ingesting PCAP and reassembling TCP flows: {pcapFile}");
        try
        {
            readerService.ReadPcap(pcapFile);
            Console.WriteLine($"    -> Discovered {reassembler.Flows.Count} unique TCP flows.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading PCAP File: {ex.Message}");
            return;
        }

        // 3. Process Flows (TLS State Machine & Decryption)
        Console.WriteLine("[3] Commencing TLS state machine and AEAD decryption (Parallel)...");
        System.Threading.Tasks.Parallel.ForEach(reassembler.Flows, kvp =>
        {
            var tuple = kvp.Key;
            var flow = kvp.Value;
            
            // In a complete implementation, you would pass the reassembled byte stream for both Client and Server
            // into the TlsRecordParser, find the Handshake Tracker, look up the ClientRandom in keyLogParser,
            // derive the keys with HKDF, create CipherSuiteEngines and NonceConstructors, and call TlsRecordDecryptor.
            Console.WriteLine($"    - Tracked flow: {tuple.SourceIp}:{tuple.SourcePort} -> {tuple.DestIp}:{tuple.DestPort}");
        });

        Console.WriteLine("Done.");
    }
}

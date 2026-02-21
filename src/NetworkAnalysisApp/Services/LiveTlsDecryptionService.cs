using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using NetworkAnalysisApp.Models;
using TlsDecryptionEngine.Core;
using TlsDecryptionEngine.Crypto;
using TlsDecryptionEngine.Kdf;
using TlsDecryptionEngine.Tls;

namespace NetworkAnalysisApp.Services
{
    public class FlowState
    {
        public ConnectionTuple Tuple { get; }
        public TcpFlow TcpFlow { get; }
        public TlsHandshakeTracker HandshakeTracker { get; } = new TlsHandshakeTracker();
        
        public int ProcessedServerRecordCount { get; set; }
        public int ServerHandshakeSequence { get; set; }
        public int ServerAppDataSequence { get; set; }
        
        public byte[]? ServerHandshakeKey { get; set; }
        public byte[]? ServerHandshakeIv { get; set; }
        
        public byte[]? ServerAppDataKey { get; set; }
        public byte[]? ServerAppDataIv { get; set; }

        public int ProcessedClientRecordCount { get; set; }
        public int ClientHandshakeSequence { get; set; }
        public int ClientAppDataSequence { get; set; }
        
        public byte[]? ClientHandshakeKey { get; set; }
        public byte[]? ClientHandshakeIv { get; set; }
        
        public byte[]? ClientAppDataKey { get; set; }
        public byte[]? ClientAppDataIv { get; set; }

        public FlowState(ConnectionTuple tuple, TcpFlow flow)
        {
            Tuple = tuple;
            TcpFlow = flow;
        }
    }

    public class LiveTlsDecryptionService
    {
        private readonly KeyLogFileParser _keyLogParser = new KeyLogFileParser();
        private readonly TcpStreamReassembler _reassembler = new TcpStreamReassembler();
        private readonly ConcurrentDictionary<ConnectionTuple, FlowState> _flowStates = new();
        private DateTime _lastKeylogWriteTime = DateTime.MinValue;

        public string KeyLogPath { get; set; } = string.Empty;

        public LiveTlsDecryptionService(string keyLogPath)
        {
            KeyLogPath = keyLogPath;
            LoadKeylog();
        }

        private void LoadKeylog()
        {
            if (string.IsNullOrWhiteSpace(KeyLogPath) || !File.Exists(KeyLogPath))
                return;

            try
            {
                var writeTime = File.GetLastWriteTime(KeyLogPath);
                if (writeTime > _lastKeylogWriteTime)
                {
                    _keyLogParser.Parse(KeyLogPath);
                    _lastKeylogWriteTime = writeTime;
                    System.Diagnostics.Debug.WriteLine($"[TLS] Reloaded keylog. File time: {writeTime}");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[TLS] Error reading keylog: {ex.Message}");
            }
        }

        private byte[]? TryDecrypt(TlsRecord record, byte[]? key, byte[]? iv, int sequenceNumber)
        {
            if (key == null || iv == null) return null;
            
            try
            {
                using var engine = new AesGcmEngine(key);
                var nonceConstructor = new NonceConstructor(iv, isTls13: true);
                for (int i = 0; i < sequenceNumber; i++) nonceConstructor.GetNextNonce();
                
                var decryptor = new TlsRecordDecryptor(engine, nonceConstructor);
                var result = decryptor.DecryptRecord(record);
                return result;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[TLS] Decryption exception: {ex.Message}");
                return null;
            }
        }

        public byte[]? ProcessPacket(PacketModel packet)
        {
            if (packet.Payload == null || packet.Payload.Length == 0) return null;
            if (string.IsNullOrEmpty(packet.SourceIp) || string.IsNullOrEmpty(packet.DestinationIp)) return null;
            if (packet.Protocol != "TLS" && packet.Protocol != "TCP") return null;

            // Ingest keylog updates occasionally, simplistic approach
            if (packet.Number % 50 == 0)
            {
                LoadKeylog();
            }

            var tuple = new ConnectionTuple
            {
                SourceIp = packet.SourceIp,
                DestIp = packet.DestinationIp,
                SourcePort = packet.SourcePort,
                DestPort = packet.DestinationPort
            };

            // Process segment into the reassembler
            _reassembler.ProcessSegment(tuple, packet.TcpSequenceNumber, packet.Payload);

            // Flow exists now for sure. 
            var canonicalTuple = tuple;
            
            // Heuristic: If DestinationPort is 443, it's highly likely Client-to-Server
            // If SourcePort is 443, it's highly likely Server-to-Client
            bool isFromServer = false;
            
            if (_reassembler.Flows.TryGetValue(canonicalTuple.GetReversed(), out var revFlow))
            {
                canonicalTuple = canonicalTuple.GetReversed();
                // Check if *this packet* is from server
                isFromServer = true;
            }
            
            // Better heuristic based on port if one of them is highly likely a server port
            if (packet.SourcePort == 443 || packet.SourcePort == 8443)
            {
                isFromServer = true;
            }
            else if (packet.DestinationPort == 443 || packet.DestinationPort == 8443)
            {
                isFromServer = false;
            }

            if (!_reassembler.Flows.TryGetValue(canonicalTuple, out var tcpFlow))
            {
                return null;
            }

            var flowState = _flowStates.GetOrAdd(canonicalTuple, t => new FlowState(t, tcpFlow));

            var activeStream = isFromServer ? tcpFlow.ServerStream : tcpFlow.ClientStream;
            byte[] activeReassembledData;
            lock (tcpFlow)
            {
                activeReassembledData = activeStream.ReassembledData;
            }

            var records = TlsRecordParser.ParseRecords(activeReassembledData);
            
            foreach (var record in records)
            {
                // Handshake Tracker needs both sides
                flowState.HandshakeTracker.ProcessRecord(record);
            }

            if (records.Count > 0)
            {
                // Parsed records
            }

            // Check if we can derive keys
            if (flowState.HandshakeTracker.ClientRandom != null && flowState.HandshakeTracker.SelectedCipherSuite != null)
            {
                var secrets = _keyLogParser.GetSecrets(flowState.HandshakeTracker.ClientRandom);
                
                // If secrets haven't been found yet, the browser may have JUST written them to disk!
                // We'll quickly poll the keylog. File.GetLastWriteTime is very fast.
                if (secrets == null)
                {
                    LoadKeylog();
                    secrets = _keyLogParser.GetSecrets(flowState.HandshakeTracker.ClientRandom);
                }

                if (secrets != null)
                {
                    if (flowState.ServerHandshakeKey == null)
                    {
                        System.Diagnostics.Debug.WriteLine($"[TLS] Flow {tuple}: Keylog Matched ClientRandom!");
                    }
                    // Defaults for TLS_AES_128_GCM_SHA256 (0x1301)
                    int keyLen = 16;
                    var hashAlg = HashAlgorithmName.SHA256;
                    
                    // Check for TLS_AES_256_GCM_SHA384 (0x1302)
                    if (flowState.HandshakeTracker.SelectedCipherSuite == 0x1302)
                    {
                        keyLen = 32;
                        hashAlg = HashAlgorithmName.SHA384;
                    }
                    else if (flowState.HandshakeTracker.SelectedCipherSuite == 0x1303)
                    {
                        // CHACHA20_POLY1305_SHA256
                        keyLen = 32;
                        hashAlg = HashAlgorithmName.SHA256;
                    }

                    // SERVER KEYS
                    if (secrets.ServerHandshakeTrafficSecret != null && flowState.ServerHandshakeKey == null)
                    {
                        flowState.ServerHandshakeKey = Tls13KeyDerivation.HKDFExpandLabel(secrets.ServerHandshakeTrafficSecret, "key", Array.Empty<byte>(), keyLen, hashAlg);
                        flowState.ServerHandshakeIv = Tls13KeyDerivation.HKDFExpandLabel(secrets.ServerHandshakeTrafficSecret, "iv", Array.Empty<byte>(), 12, hashAlg);
                    }

                    if (secrets.ServerTrafficSecret0 != null && flowState.ServerAppDataKey == null)
                    {
                        flowState.ServerAppDataKey = Tls13KeyDerivation.HKDFExpandLabel(secrets.ServerTrafficSecret0, "key", Array.Empty<byte>(), keyLen, hashAlg);
                        flowState.ServerAppDataIv = Tls13KeyDerivation.HKDFExpandLabel(secrets.ServerTrafficSecret0, "iv", Array.Empty<byte>(), 12, hashAlg);
                    }

                    // CLIENT KEYS
                    if (secrets.ClientHandshakeTrafficSecret != null && flowState.ClientHandshakeKey == null)
                    {
                        flowState.ClientHandshakeKey = Tls13KeyDerivation.HKDFExpandLabel(secrets.ClientHandshakeTrafficSecret, "key", Array.Empty<byte>(), keyLen, hashAlg);
                        flowState.ClientHandshakeIv = Tls13KeyDerivation.HKDFExpandLabel(secrets.ClientHandshakeTrafficSecret, "iv", Array.Empty<byte>(), 12, hashAlg);
                    }

                    if (secrets.ClientTrafficSecret0 != null && flowState.ClientAppDataKey == null)
                    {
                        flowState.ClientAppDataKey = Tls13KeyDerivation.HKDFExpandLabel(secrets.ClientTrafficSecret0, "key", Array.Empty<byte>(), keyLen, hashAlg);
                        flowState.ClientAppDataIv = Tls13KeyDerivation.HKDFExpandLabel(secrets.ClientTrafficSecret0, "iv", Array.Empty<byte>(), 12, hashAlg);
                    }
                }
            }

            // Attempt decryption on records for the ACTIVE stream
            byte[]? returnedPayload = null;
            var latestRecords = records; // We already parsed them above
            
            // Reference the correct counters/keys based on direction
            int processedCount = isFromServer ? flowState.ProcessedServerRecordCount : flowState.ProcessedClientRecordCount;
            int handshakeSeq = isFromServer ? flowState.ServerHandshakeSequence : flowState.ClientHandshakeSequence;
            int appDataSeq = isFromServer ? flowState.ServerAppDataSequence : flowState.ClientAppDataSequence;
            
            byte[]? handshakeKey = isFromServer ? flowState.ServerHandshakeKey : flowState.ClientHandshakeKey;
            byte[]? handshakeIv = isFromServer ? flowState.ServerHandshakeIv : flowState.ClientHandshakeIv;
            
            byte[]? appDataKey = isFromServer ? flowState.ServerAppDataKey : flowState.ClientAppDataKey;
            byte[]? appDataIv = isFromServer ? flowState.ServerAppDataIv : flowState.ClientAppDataIv;
            
            for (int i = processedCount; i < latestRecords.Count; i++)
            {
                var record = latestRecords[i];
                if (record.ContentType == TlsContentType.ApplicationData)
                {
                    bool decrypted = false;
                    
                    // Try Handshake Key
                    if (handshakeKey != null)
                    {
                            var plain = TryDecrypt(record, handshakeKey, handshakeIv, handshakeSeq);
                            if (plain != null)
                            {
                                handshakeSeq++;
                                decrypted = true;
                                processedCount++;
                                if (returnedPayload == null) returnedPayload = plain; 
                                continue;
                            }
                    }

                    // Try AppData Key (if handshake fails / isn't active)
                    if (!decrypted && appDataKey != null)
                    {
                            var plain = TryDecrypt(record, appDataKey, appDataIv, appDataSeq);
                            if (plain != null)
                            {
                                appDataSeq++;
                                decrypted = true;
                                processedCount++;
                                if (returnedPayload == null) returnedPayload = plain; 
                                continue;
                            }
                    }

                    if (!decrypted)
                    {
                        System.Diagnostics.Debug.WriteLine($"[TLS] Flow {tuple}: Could not decrypt ApplicationData record index {i} (Direction: {(isFromServer ? "Server" : "Client")})");
                        // Break out of loop, don't advance ProcessedCount, so we try again next packet!
                        break;
                    }
                }
                else
                {
                    // Cleartext records
                    processedCount++;
                }
            }
            
            // Save state back
            if (isFromServer)
            {
                flowState.ProcessedServerRecordCount = processedCount;
                flowState.ServerHandshakeSequence = handshakeSeq;
                flowState.ServerAppDataSequence = appDataSeq;
            }
            else
            {
                flowState.ProcessedClientRecordCount = processedCount;
                flowState.ClientHandshakeSequence = handshakeSeq;
                flowState.ClientAppDataSequence = appDataSeq;
            }
            
            return returnedPayload;
        }

        public void Clear()
        {
            _flowStates.Clear();
            // A more robust app would recreate reassembler but creating a new one is best since Flows is IReadOnlyDictionary
            // _reassembler.Flows.Clear() doesn't work. We should just let the GC handle it or add a Clear to TcpStreamReassembler.
        }
    }
}

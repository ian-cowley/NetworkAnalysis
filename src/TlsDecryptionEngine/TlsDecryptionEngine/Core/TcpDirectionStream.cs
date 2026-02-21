using System;
using System.Collections.Generic;
using System.Linq;

namespace TlsDecryptionEngine.Core;

public class TcpDirectionStream
{
    private uint _expectedSequenceNumber;
    private bool _isInitialized;
    private readonly MemoryStream _reassembledData = new();
    private readonly Dictionary<uint, byte[]> _outOfOrderSegments = new();

    public byte[] ReassembledData => _reassembledData.ToArray();

    public void AddSegment(uint seqNum, byte[] payload)
    {
        if (payload == null || payload.Length == 0) return;

        if (!_isInitialized)
        {
            _expectedSequenceNumber = seqNum;
            _isInitialized = true;
        }

        if (seqNum == _expectedSequenceNumber)
        {
            // In order segment
            _reassembledData.Write(payload, 0, payload.Length);
            _expectedSequenceNumber += (uint)payload.Length;

            // Check out-of-order buffer
            CheckBuffer();
        }
        else if (IsGreaterThan(seqNum, _expectedSequenceNumber))
        {
            // Out of order segment
            if (!_outOfOrderSegments.ContainsKey(seqNum))
            {
                _outOfOrderSegments[seqNum] = payload;
            }
        }
        else
        {
            // Overlapping or retransmission segment. Basic handling for exact overlap/retransmission:
            // Since seqNum < expectedSequenceNumber, this is an old packet. 
            // If the packet extends beyond expectedSequenceNumber, we append the difference.
            long difference = (long)seqNum + payload.Length - _expectedSequenceNumber;
            if (difference > 0)
            {
                int offset = payload.Length - (int)difference;
                _reassembledData.Write(payload, offset, payload.Length - offset);
                _expectedSequenceNumber += (uint)(payload.Length - offset);
                CheckBuffer();
            }
        }
    }

    private void CheckBuffer()
    {
        bool added;
        do
        {
            added = false;
            
            // Exact sequence match
            if (_outOfOrderSegments.TryGetValue(_expectedSequenceNumber, out var payload))
            {
                _reassembledData.Write(payload, 0, payload.Length);
                _outOfOrderSegments.Remove(_expectedSequenceNumber);
                _expectedSequenceNumber += (uint)payload.Length;
                added = true;
            }
            else
            {
                // Check if any out-of-order segment overlaps with our expected seq
                var keys = _outOfOrderSegments.Keys.ToList();
                foreach (var key in keys)
                {
                    var segPayload = _outOfOrderSegments[key];
                    if (!IsGreaterThan(key, _expectedSequenceNumber) && IsGreaterThan(key + (uint)segPayload.Length, _expectedSequenceNumber))
                    {
                        uint offset = _expectedSequenceNumber - key;
                        int lengthToTake = segPayload.Length - (int)offset;
                        if (lengthToTake > 0)
                        {
                            _reassembledData.Write(segPayload, (int)offset, lengthToTake);
                            _expectedSequenceNumber += (uint)lengthToTake;
                            added = true;
                        }
                        _outOfOrderSegments.Remove(key);
                        break; // exit foreach and try the do-while loop again
                    }
                    else if (!IsGreaterThan(key + (uint)segPayload.Length, _expectedSequenceNumber))
                    {
                         // This entire segment is already in the reassembled buffer. Discard it.
                         _outOfOrderSegments.Remove(key);
                    }
                }
            }
        }
        while (added);
    }
    
    private bool IsGreaterThan(uint s1, uint s2)
    {
        // TCP sequence numbers wrap around contextually. Simplest heuristic: 
        // if difference is less than 2^31, it's greater.
        return (s1 - s2) < 0x80000000;
    }
}

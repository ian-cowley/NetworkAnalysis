using System.Collections.Concurrent;
using System.Collections.Generic;

namespace TlsDecryptionEngine.Core;

public class TcpStreamReassembler
{
    private readonly ConcurrentDictionary<ConnectionTuple, TcpFlow> _flows = new();

    public IReadOnlyDictionary<ConnectionTuple, TcpFlow> Flows => _flows;

    public void ProcessSegment(ConnectionTuple tuple, uint sequenceNumber, byte[] payload)
    {
        if (payload == null || payload.Length == 0) return;

        var reversed = tuple.GetReversed();

        // Check reversed first (is from server?)
        if (_flows.TryGetValue(reversed, out var revFlow))
        {
            lock (revFlow)
            {
                revFlow.ServerStream.AddSegment(sequenceNumber, payload);
            }
            return;
        }

        // Get or add flow for client-to-server direction
        var flow = _flows.GetOrAdd(tuple, t => new TcpFlow(t));
        
        lock (flow)
        {
            flow.ClientStream.AddSegment(sequenceNumber, payload);
        }
    }
}

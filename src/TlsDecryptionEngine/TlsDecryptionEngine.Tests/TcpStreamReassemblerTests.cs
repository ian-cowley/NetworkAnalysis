using System;
using System.Linq;
using Xunit;
using TlsDecryptionEngine.Core;

namespace TlsDecryptionEngine.Tests;

public class TcpStreamReassemblerTests
{
    [Fact]
    public void Reassembler_Handles_InOrder_Segments()
    {
        var reassembler = new TcpStreamReassembler();
        var tuple = new ConnectionTuple("10.0.0.1", 1234, "10.0.0.2", 443);

        reassembler.ProcessSegment(tuple, 100, new byte[] { 1, 2, 3 });
        reassembler.ProcessSegment(tuple, 103, new byte[] { 4, 5 });

        var flow = reassembler.Flows[tuple];
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, flow.ClientStream.ReassembledData);
    }

    [Fact]
    public void Reassembler_Handles_OutOfOrder_Segments()
    {
        var reassembler = new TcpStreamReassembler();
        var tuple = new ConnectionTuple("10.0.0.1", 1234, "10.0.0.2", 443);

        reassembler.ProcessSegment(tuple, 100, new byte[] { 1, 2, 3 });
        // Missing 103...
        reassembler.ProcessSegment(tuple, 105, new byte[] { 6, 7 });
        // Now 103 arrives
        reassembler.ProcessSegment(tuple, 103, new byte[] { 4, 5 });

        var flow = reassembler.Flows[tuple];
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6, 7 }, flow.ClientStream.ReassembledData);
    }

    [Fact]
    public void Reassembler_Handles_Overlapping_Retransmissions()
    {
        var reassembler = new TcpStreamReassembler();
        var tuple = new ConnectionTuple("10.0.0.1", 1234, "10.0.0.2", 443);

        reassembler.ProcessSegment(tuple, 100, new byte[] { 1, 2, 3, 4 });
        
        // Retransmission with overlapping new data
        reassembler.ProcessSegment(tuple, 102, new byte[] { 3, 4, 5, 6 });

        var flow = reassembler.Flows[tuple];
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6 }, flow.ClientStream.ReassembledData);
    }
}

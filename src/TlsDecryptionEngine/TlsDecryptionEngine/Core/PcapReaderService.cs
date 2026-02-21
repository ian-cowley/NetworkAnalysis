using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System;

namespace TlsDecryptionEngine.Core;

public class PcapReaderService
{
    private readonly TcpStreamReassembler _reassembler;

    public PcapReaderService(TcpStreamReassembler reassembler)
    {
        _reassembler = reassembler;
    }

    public void ReadPcap(string filePath)
    {
        using var device = new CaptureFileReaderDevice(filePath);
        device.Open();
        
        device.OnPacketArrival += (sender, e) =>
        {
            var packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);
            var tcpPacket = packet.Extract<TcpPacket>();
            var ipPacket = packet.Extract<IPPacket>();

            if (tcpPacket != null && ipPacket != null)
            {
                if (tcpPacket.PayloadData != null && tcpPacket.PayloadData.Length > 0)
                {
                    var tuple = new ConnectionTuple(
                        ipPacket.SourceAddress.ToString(),
                        tcpPacket.SourcePort,
                        ipPacket.DestinationAddress.ToString(),
                        tcpPacket.DestinationPort
                    );

                    _reassembler.ProcessSegment(tuple, (uint)tcpPacket.SequenceNumber, tcpPacket.PayloadData);
                }
            }
        };

        device.Capture();
    }
}

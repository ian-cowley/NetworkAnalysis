using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace TlsDecryptionEngine.Tls;

public class TlsRecordParser
{
    public static List<TlsRecord> ParseRecords(ReadOnlySpan<byte> streamData)
    {
        var records = new List<TlsRecord>();
        int offset = 0;

        while (offset + 5 <= streamData.Length)
        {
            var typeByte = streamData[offset];
            if (!Enum.IsDefined(typeof(TlsContentType), typeByte))
            {
                // Unrecognized or corrupted stream, we can't reliably parse further
                break;
            }

            var contentType = (TlsContentType)typeByte;
            var version = BinaryPrimitives.ReadUInt16BigEndian(streamData.Slice(offset + 1, 2));
            var length = BinaryPrimitives.ReadUInt16BigEndian(streamData.Slice(offset + 3, 2));

            if (offset + 5 + length > streamData.Length)
            {
                // Incomplete record, need more data
                break;
            }

            var payload = streamData.Slice(offset + 5, length).ToArray();
            
            records.Add(new TlsRecord
            {
                ContentType = contentType,
                Version = version,
                Length = length,
                Payload = payload
            });

            offset += 5 + length;
        }

        return records;
    }
}

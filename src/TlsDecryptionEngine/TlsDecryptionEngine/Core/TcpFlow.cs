using System.Collections.Generic;

namespace TlsDecryptionEngine.Core;

public class TcpFlow
{
    public ConnectionTuple ClientToServerTuple { get; }
    
    public TcpDirectionStream ClientStream { get; }
    public TcpDirectionStream ServerStream { get; }

    public TcpFlow(ConnectionTuple clientToServerTuple)
    {
        ClientToServerTuple = clientToServerTuple;
        ClientStream = new TcpDirectionStream();
        ServerStream = new TcpDirectionStream();
    }
}

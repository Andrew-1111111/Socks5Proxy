namespace Socks5Proxy.Server.Protocol.UDP;

/// <summary>
/// Buffer for UDP fragmentation reassembly.
/// </summary>
internal class FragmentBuffer
{
    public byte[][] Parts = new byte[256][];
    public int Received;
    public int Expected = -1;
}

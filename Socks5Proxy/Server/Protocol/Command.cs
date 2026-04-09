namespace Socks5Proxy.Server.Protocol;

/// <summary>
/// SOCKS5 commands
/// </summary>
internal static class Command
{
    /// <summary>
    /// CONNECT command - establish a TCP connection
    /// </summary>
    public const byte Connect = 0x01;

    /// <summary>
    /// BIND command - bind to a port for incoming connections
    /// </summary>
    public const byte Bind = 0x02;

    /// <summary>
    /// UDP ASSOCIATE command - establish UDP relay
    /// </summary>
    public const byte UdpAssociate = 0x03;
}
namespace Socks5Proxy.Server.Protocol;

/// <summary>
/// Constants and enums for SOCKS5 protocol values.
/// </summary>
internal static class Socks5Protocol
{
    /// <summary>
    /// SOCKS version 5
    /// </summary>
    public const byte Version = 0x05;

    /// <summary>
    /// Reserved byte value
    /// </summary>
    public const byte Reserved = 0x00;
}
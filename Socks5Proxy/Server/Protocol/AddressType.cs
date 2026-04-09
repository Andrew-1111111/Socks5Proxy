namespace Socks5Proxy.Server.Protocol;

/// <summary>
/// SOCKS5 address types
/// </summary>
internal static class AddressType
{
    /// <summary>
    /// IPv4 address
    /// </summary>
    public const byte IPv4 = 0x01;

    /// <summary>
    /// Domain name
    /// </summary>
    public const byte DomainName = 0x03;

    /// <summary>
    /// IPv6 address
    /// </summary>
    public const byte IPv6 = 0x04;
}
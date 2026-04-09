namespace Socks5Proxy.Server.Protocol;

/// <summary>
/// SOCKS5 reply codes
/// </summary>
internal static class ReplyCode
{
    /// <summary>
    /// Succeeded
    /// </summary>
    public const byte Succeeded = 0x00;

    /// <summary>
    /// General SOCKS server failure
    /// </summary>
    public const byte GeneralFailure = 0x01;

    /// <summary>
    /// Connection not allowed by ruleset
    /// </summary>
    public const byte ConnectionNotAllowed = 0x02;

    /// <summary>
    /// Network unreachable
    /// </summary>
    public const byte NetworkUnreachable = 0x03;

    /// <summary>
    /// Host unreachable
    /// </summary>
    public const byte HostUnreachable = 0x04;

    /// <summary>
    /// Connection refused
    /// </summary>
    public const byte ConnectionRefused = 0x05;

    /// <summary>
    /// TTL expired
    /// </summary>
    public const byte TtlExpired = 0x06;

    /// <summary>
    /// Command not supported
    /// </summary>
    public const byte CommandNotSupported = 0x07;

    /// <summary>
    /// Address type not supported
    /// </summary>
    public const byte AddressTypeNotSupported = 0x08;
}
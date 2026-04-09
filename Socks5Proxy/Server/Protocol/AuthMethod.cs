namespace Socks5Proxy.Server.Protocol;

/// <summary>
/// SOCKS5 authentication methods
/// </summary>
internal static class AuthMethod
{
    /// <summary>
    /// No authentication required
    /// </summary>
    public const byte NoAuth = 0x00;

    /// <summary>
    /// GSSAPI authentication
    /// </summary>
    public const byte GSSAPI = 0x01;

    /// <summary>
    /// Username/password authentication
    /// </summary>
    public const byte UsernamePassword = 0x02;

    /// <summary>
    /// No acceptable methods
    /// </summary>
    public const byte NoAcceptableMethods = 0xFF;
}
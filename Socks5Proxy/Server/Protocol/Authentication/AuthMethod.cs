namespace Socks5Proxy.Server.Protocol.Autentification;

/// <summary>
/// SOCKS5 authentication methods
/// </summary>
internal enum AuthMethod : byte
{
    /// <summary>
    /// No authentication required
    /// </summary>
    NoAuth = 0x00,

    /// <summary>
    /// GSSAPI authentication
    /// </summary>
    GSSAPI = 0x01,

    /// <summary>
    /// Username/password authentication
    /// </summary>
    UsernamePassword = 0x02,

    /// <summary>
    /// No acceptable methods
    /// </summary>
    NoAcceptableMethods = 0xFF
}
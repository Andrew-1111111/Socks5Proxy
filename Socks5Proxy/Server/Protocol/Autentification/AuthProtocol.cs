namespace Socks5Proxy.Server.Protocol;

/// <summary>
/// SOCKS5 Username/Password authentication protocol constants (RFC 1929).
/// </summary>
internal static class AuthProtocol
{
    /// <summary>
    /// Authentication sub-negotiation version.
    /// </summary>
    public const byte Version = 0x01;

    /// <summary>
    /// Possible authentication result status codes.
    /// </summary>
    internal static class Status
    {
        // Authentication succeeded.
        public const byte Success = 0x00;

        // Authentication failed.
        public const byte Failure = 0x01;
    }
}
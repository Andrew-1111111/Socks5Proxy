using System.Net;

namespace Socks5Proxy.Server.Protocol.DNS;

/// <summary>
/// Represents parsed DNS result.
/// Immutable.
/// </summary>
internal readonly struct DnsResult(IPAddress? address, int ttl, bool truncated)
{
    public static readonly DnsResult Invalid = new(null, 30, false);

    public IPAddress? Address { get; } = address;
    public int Ttl { get; } = ttl;
    public bool Truncated { get; } = truncated;
}
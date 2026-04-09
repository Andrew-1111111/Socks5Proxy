using System;
using System.Net;

namespace Socks5Proxy.Server.Protocol.UDP;

/// <summary>
/// DNS cache entry with resolved addresses and expiry time.
/// </summary>
internal class DnsCacheEntry
{
    /// <summary>Resolved IP addresses (never null).</summary>
    public IPAddress[] Addresses { get; set; } = [];

    /// <summary>Expiry time of this cache entry.</summary>
    public DateTime Expiry { get; set; }
}